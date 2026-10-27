namespace Respawn.Core
{
    public enum ResultStatus
    {
        Success,
        Failure,
        AlreadyExists,
        NotFound,
        AccessDenied
    }

    public class TechniqueResult
    {
        public ResultStatus Status { get; set; }
        public string? Message { get; set; }

        public static TechniqueResult Ok(string message) => new TechniqueResult
        {
            Status = ResultStatus.Success,
            Message = message
        };

        public static TechniqueResult Fail(string message) => new TechniqueResult
        {
            Status = ResultStatus.Failure,
            Message = message
        };

        public static TechniqueResult Exists(string message) => new TechniqueResult
        {
            Status = ResultStatus.AlreadyExists,
            Message = message
        };

        public static TechniqueResult NotFound(string message) => new TechniqueResult
        {
            Status = ResultStatus.NotFound,
            Message = message
        };

        public static TechniqueResult Denied(string message) => new TechniqueResult
        {
            Status = ResultStatus.AccessDenied,
            Message = message
        };
    }
}