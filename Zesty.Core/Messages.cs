namespace Zesty.Core
{
    public static class Messages
    {
        public static readonly string AccessDenied = "Access denied";
        public static readonly string AuthorizationFailed = "Authorization failed";
        public static readonly string ObjectNotFound = "Object not found";
        public static readonly string ArgumentNotFound = "Required argument was not found";
        public static readonly string Done = "Done";
        public static readonly string LoginFailed = "Login failed";
        public static readonly string LoginBanned = "You tried to much invalid accesses. You're banned for {0} minutes";
        public static readonly string PasswordExpired = "Password expired";
        public static readonly string WrongApiOutput = "Wrong API output";
        public static readonly string SettingsLoaded = "Application settings loaded";
        public static readonly string TokenMissing = "Required token is missing";
        public static readonly string LanguageMissing = "Required argument is missing";
        public static readonly string KeyNotFound = "Key not found";
        public static readonly string SettingNotFound = "Setting not found with key {0}";
        public static readonly string RequestIsNull = "Request is null";
        public static readonly string MissingRequireArgument = "The required argument {0} is null.";
        public static readonly string Success = "Success";
        public static readonly string Failure = "Failure";
        public static readonly string GenericFailure = "Something went wrong :(";
        public static readonly string WrongPassword = "Wrong password";
        public static readonly string PasswordChangeSame = "Old and new password are the same";
        public static readonly string PasswordDontMatch = "New password e confirm don't match";
        public static readonly string UserNotFound = "User not found";
        public static readonly string UserCannotCreateBecauseAlreadyExists = "User already exists";
    }
}
