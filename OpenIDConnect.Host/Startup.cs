using Microsoft.Owin;
using Owin;
using IdentityAdmin.Logging;
using Serilog;
using Autofac;
using OpenIDConnect.IdentityManager;
using OpenIDConnect.IdentityAdmin;
using OpenIDConnect.IdentityServer;


[assembly: OwinStartup(typeof(OpenIDConnect.Host.Startup))]

namespace OpenIDConnect.Host
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            Log.Logger = new LoggerConfiguration()
                .MinimumLevel.Debug()
                .WriteTo.Trace()
                .CreateLogger();

            //LogProvider.SetCurrentLogProvider(new DiagnosticsTraceLogProvider());
            LogProvider.SetCurrentLogProvider(new DiagnosticsTraceLogProvider());

            var builder = new ContainerBuilder();

            Modules.Register(builder);

            var container = builder.Build();

            using (var scope = container.BeginLifetimeScope())
            {
                app.Map("/core", coreApp =>
                {
                    scope.Resolve<IdentityServerBootstrapper>().Run(coreApp);
                });

                app.Map("/admin", adminApp =>
                {
                    scope.Resolve<IdentityAdminBootstrapper>().Run(adminApp);
                });

                app.Map("/manage", manageApp =>
                {
                    scope.Resolve<IdentityManagerBootstrapper>().Run(manageApp);
                });
                //app.Map("/memory", memoryApp =>
                //{
               // using IdentityManager;
               // using IdentityManager.Configuration;
               // using System.Collections.Generic;

                //    var factory = new IdentityManagerServiceFactory
                //    {

                //    };

                //    var rand = new System.Random();
                //    var users = new List<InMemoryUser>();
                //    var roles = new List<InMemoryRole>();

                //    factory.Register(new Registration<ICollection<InMemoryUser>>(users));
                //    factory.Register(new Registration<ICollection<InMemoryRole>>(roles));
                //    factory.IdentityManagerService = new Registration<IIdentityManagerService, InMemoryIdentityManagerService>();

                //    memoryApp.UseIdentityManager(new IdentityManagerOptions
                //    {
                //        Factory = factory,
                //    });
                //});
            }
        }
    }
}