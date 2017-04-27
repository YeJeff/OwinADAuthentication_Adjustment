using Microsoft.Owin;
using Owin;

[assembly:OwinStartupAttribute(typeof(OWINAndAD.Startup))]
namespace OWINAndAD
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}