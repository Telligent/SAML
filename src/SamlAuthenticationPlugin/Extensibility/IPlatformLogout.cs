﻿using Telligent.Evolution.Extensibility.Version1;

namespace Verint.Services.SamlAuthenticationPlugin.Extensibility
{
    public interface IPlatformLogout : ISingletonPlugin, ICategorizedPlugin
    {

        bool Enabled { get; }

        /// <summary>
        /// Logs the user out of the Telligent platform
        /// </summary>
        void Logout();

    }
}
