using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;


namespace Singularity.Credentials
{
    public abstract class CredentialValidator
    {
        bool isValid, validationAttempted = false;
        public string UserName { get; protected set; }
        public string AuthenticationType { get; private set; }

        Action success;
        Action failed;

        public event Action SuccessfulValidation
        {
            add
            {
                success += value;
            }
            
            remove
            {

            }
        }

        public event Action FailedValidation
        {
            add
            {
                failed += value;
            }

            remove
            {

            }
        }


        /// <summary>
        ///This operation is idempotent.
        /// </summary>
        /// <returns></returns>
        public bool Validate()
        {
            if (!validationAttempted)
            {
                isValid = _Validate ();
                validationAttempted = true;

                if (isValid && success != null)
                    success ();

                if (!isValid && failed != null)
                    failed ();
            }

            return isValid;
        }

        public bool IsValid
        {
            get
            {
                return Validate();
            }
        }

        protected CredentialValidator(string UserName, string AuthenticationType)
        {
            this.UserName = UserName;
            this.AuthenticationType = AuthenticationType;
        }

        protected abstract bool _Validate();

        public static implicit operator bool(CredentialValidator cv)
        {
            return cv._Validate ();
        }

        public static CredentialValidator CreateCredentialValidator(string user)
        {
            return new AdHoc(user);
        }

        public static CredentialValidator CreateCredentialValidator(string user, string pass, Action success = null, Action failed = null)
        {
            if (user != null)
            {
                var tokens = user.Split ('@');
                var domain = tokens[tokens.Length - 1].ToLower();

                CredentialValidator credentials;

                switch (domain)
                {
                    case "okstate.edu":
                        credentials = new OkeyValidation (user, pass);
                        break;
                    default:
                        throw new Exception ();
                }

                credentials.success = success;
                credentials.failed = failed;

                return credentials;
            }
            else
            {
                throw new Exception ();
            }
        }


        /// <summary>
        /// A user friendly message indicating successful validation or the reason for failure.
        /// </summary>
        /// <returns></returns>
        protected internal virtual string GetValidationMessage()
        {
            return UserName + " submitted " + (Validate () ? "valid" : "invalid") + " credentials.";
        }

        public override string ToString()
        {
            return GetValidationMessage ();
        }

        protected virtual IEnumerable<CredentialValidator> GetCredentialsValidators()
        {
            yield return this;
        }


        //TODO: Check for duplicates...
        public static CredentialValidator Combine (CredentialValidator x, CredentialValidator y)
        {
            var xs = x.GetCredentialsValidators().Union(y.GetCredentialsValidators());

            return new AggregateValidatior(xs);
        }

        public static CredentialValidator operator +(CredentialValidator x, CredentialValidator y)
        {
            return Combine(x, y);
        }


        class AggregateValidatior : CredentialValidator
        {

            List<CredentialValidator> credentials;

            public AggregateValidatior(IEnumerable<CredentialValidator> xs)
                : base (xs.First ().UserName, xs.Aggregate ("", (x, y) => x + y.AuthenticationType + Environment.NewLine))
            {
                credentials = new List<CredentialValidator> (xs);

                foreach (var x in credentials)
                {
                    x.validationAttempted = false;

                    if (x.success != null)
                        this.success += x.success;

                    if (x.failed != null)
                        this.failed += x.failed;
                }

            }

            protected override IEnumerable<CredentialValidator> GetCredentialsValidators()
            {
                return credentials;
            }

            protected internal override string GetValidationMessage()
            {
                if (Validate ())
                    return "Credentials are valid";
                else
                {
                    var sb = new StringBuilder ();

                    foreach (var cred in credentials.Where (x => !x.IsValid))
                    {
                        sb.AppendLine (cred.AuthenticationType + ": " + cred.GetValidationMessage ());
                    }

                    return sb.ToString ();
                }
            }
            
            protected override bool _Validate()
            {
                return credentials.All (x => x._Validate ());
            }
        }
    }
    
    class AdHoc : CredentialValidator
    {

        public AdHoc(string user) : base(user, "AdHoc")
        {

        }

        protected override bool _Validate()
        {
            return true;
        }         
    }
}