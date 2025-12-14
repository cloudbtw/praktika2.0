namespace WebApplication10.classes
{
    public class OrderItem
    {
        public int Id { get; set; }
        public int OrderId { get; set; }
        public int SneakerId { get; set; }
        public int Qty { get; set; }
        public decimal Price { get; set; }
    }
}