using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;

namespace Singularity.Credentials
{
    class OkeyValidation : CredentialValidator
    {
        string user;
        string pass;

        public OkeyValidation(string user, string pass)
            : base (user, "Okey Authentication")
        {
            this.user = user;
            this.pass = pass;
        }

        protected internal override string GetValidationMessage()
        {
            return _Validate () ? base.GetValidationMessage () : "That username/password combination is not valid.";
        }

        protected override bool _Validate()
        {
            using (var adContext = new PrincipalContext (ContextType.Domain, "ad.okstate.edu"))
            {
                return adContext.ValidateCredentials (user, pass);
            }
        }
    }
}
