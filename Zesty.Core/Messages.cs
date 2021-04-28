namespace Zesty.Core
{
    static class Messages
    {
        internal static readonly string AccessDenied = "Access denied";
        internal static readonly string AuthorizationFailed = "Authorization failed";
        internal static readonly string ObjectNotFound = "Object not found";
        internal static readonly string ArgumentNotFound = "Required argument was not found";
        internal static readonly string Done = "Done";
        internal static readonly string LoginFailed = "Login failed";
        internal static readonly string LoginBanned = "You tried to much invalid accesses. You're banned for {0} minutes";
        internal static readonly string PasswordExpired = "Password expired";
        internal static readonly string WrongApiOutput = "Wrong API output";
        internal static readonly string SettingsLoaded = "Application settings loaded";
        internal static readonly string TokenMissing = "Required token is missing";
        internal static readonly string LanguageMissing = "Required argument is missing";
        internal static readonly string KeyNotFound = "Key not found";
        internal static readonly string SettingNotFound = "Setting not found with key {0}";
        internal static readonly string RequestIsNull = "Request is null";
        internal static readonly string MissingRequireArgument = "The required argument {0} is null.";
        internal static readonly string Success = "Success";
        internal static readonly string Failure = "Failure";
        internal static readonly string GenericFailure = "Something went wrong :(";
        internal static readonly string WrongPassword = "Wrong password";
        internal static readonly string PasswordChangeSame = "Old and new password are the same";
        internal static readonly string PasswordDontMatch = "New password e confirm don't match";
        internal static readonly string UserNotFound = "User not found";
        internal static readonly string UserCannotCreateBecauseAlreadyExists = "User already exists";
    }
}
