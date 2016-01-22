﻿using System;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Reflection;
using OpenIDConnect.Core.Constants;

namespace OpenIDConnect.IdentityServer.MembershipReboot.Extensions
{
    public static class PropertyInfoExtensions
    {
        public static bool IsValidAsPropertyMetadata(this PropertyInfo property)
        {
            if (property == null)
            {
                throw new ArgumentNullException(nameof(property));
            }

            if (property.IsReadOnly())
            {
                return false;
            }

            var type = Nullable.GetUnderlyingType(property.PropertyType) ?? property.PropertyType;

            if (type.IsInterface)
            {
                return false;
            }

            if (type.IsClass && type != typeof(string))
            {
                return false;
            }

            if (type.IsValueType && !type.IsPrimitive)
            {
                return false;
            }

            return true;
        }

        public static bool IsReadOnly(this PropertyInfo property)
        {
            if (property == null)
            {
                throw new ArgumentNullException(nameof(property));
            }

            if (!property.CanWrite) return true;

            return property
                .GetCustomAttributes<ReadOnlyAttribute>(false).Any(x => x.IsReadOnly);
        }

        public static bool IsRequired(this PropertyInfo property)
        {
            if (property == null)
            {
                throw new ArgumentNullException(nameof(property));
            }

            if (property.PropertyType.IsValueType && property.PropertyType.IsPrimitive)
            {
                return true;
            }

            return property.GetCustomAttributes<RequiredAttribute>().Any();
        }

        public static string GetName(this PropertyInfo property)
        {
            if (property == null)
            {
                throw new ArgumentNullException(nameof(property));
            }

            var display = property.GetCustomAttribute<DisplayAttribute>();
            if (display != null)
            {
                return display.Name;
            }

            var displayName = property.GetCustomAttribute<DisplayNameAttribute>();
            if (displayName != null)
            {
                return displayName.DisplayName;
            }

            return property.Name;
        }

        public static string GetPropertyDataType(this PropertyInfo property)
        {
            if (property == null)
            {
                throw new ArgumentNullException(nameof(property));
            }

            var dataTypeAttr = property.GetCustomAttribute<DataTypeAttribute>();
            if (dataTypeAttr != null)
            {
                switch (dataTypeAttr.DataType)
                {
                    case DataType.Password:
                        return PropertyTypes.Password;
                    case DataType.EmailAddress:
                        return PropertyTypes.Email;
                    case DataType.Url:
                        return PropertyTypes.Url;
                }
            }

            return property.PropertyType.GetPropertyDataType();
        }

        public static string GetPropertyDataType(this Type type)
        {
            if (type == null)
            {
                throw new ArgumentNullException(nameof(type));
            }

            type = Nullable.GetUnderlyingType(type) ?? type;

            if (type == typeof(bool))
            {
                return PropertyTypes.Boolean;
            }

            if (type == typeof(short) ||
                type == typeof(int) ||
                type == typeof(long) ||
                type == typeof(float) ||
                type == typeof(double) ||
                type == typeof(decimal))
            {
                return PropertyTypes.Number;
            }

            return PropertyTypes.String;
        }
    }
}
