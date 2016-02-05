﻿using Microsoft.AspNet.Builder;
using Microsoft.AspNet.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace OpenIDConnect.Authorization.Api
{    
    using Data.UsersApi.Repositories;
    using Microsoft.Data.Entity;

    using Newtonsoft.Json.Serialization;

    using OpenIDConnect.Authorization.Data.EntityFramework.Context;
    using OpenIDConnect.Authorization.Data.EntityFramework.Repositories;
    using OpenIDConnect.Authorization.Domain.Repositories;

    public class Startup
    {
        public Startup(IHostingEnvironment env)
        {
            // Set up configuration sources.
            var builder = new ConfigurationBuilder()
                .AddJsonFile("appsettings.json")
                .AddEnvironmentVariables();

            this.Configuration = builder.Build();
        }

        public IConfigurationRoot Configuration { get; set; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddEntityFramework()
                .AddSqlServer()
                .AddDbContext<AuthorizationDbContext>(options =>
                    options.UseSqlServer(this.Configuration["Data:DefaultConnection:ConnectionString"]));

            // Add framework services.
            services.AddMvc().AddJsonOptions(options =>
            {
                options.SerializerSettings.ContractResolver =
                    new CamelCasePropertyNamesContractResolver();
            });

            // Add CORS support
            services.AddCors(options =>
            {
                options.AddPolicy("AllowAllOrigins",
                    builder => builder.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod());
            });

            services.AddScoped<IClientsRepository, EntityFrameworkClientsRepository>();
            services.AddScoped<IClientGroupsRepository, EntityFrameworkClientGroupsRepository>();
            services.AddScoped<IGroupClaimsRepository, EntityFrameworkGroupClaimsRepository> ();

            var usersApiUri = Configuration["Data:UsersApi:Uri"];

            services.AddScoped<IClientUsersRepository, UsersApiClientUsersRepository>(p => new UsersApiClientUsersRepository(usersApiUri));
            services.AddScoped<IUsersRepository, UsersApiUsersRepository>(p => new UsersApiUsersRepository(usersApiUri, p.GetService<IGroupClaimsRepository>()));
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            loggerFactory.AddConsole(this.Configuration.GetSection("Logging"));
            loggerFactory.AddDebug();

            app.UseCors("AllowAllOrigins");         // TODO: allow collection of allowed origins per client
            app.UseIISPlatformHandler();
            app.UseStaticFiles();
            app.UseMvc();            
        }

        // Entry point for the application.
        public static void Main(string[] args) => WebApplication.Run<Startup>(args);
    }
}