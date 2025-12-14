namespace WebApplication10.classes
{
    public class Review
    {
        public int Id { get; set; }
        public int SneakerId { get; set; }
        public int UserId { get; set; }
        public string Text { get; set; } = "";
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    }
}