using System.Collections.Generic;

namespace WebApplication10.classes
{
    public class Order
    {
        public int Id { get; set; }
        public int UserId { get; set; }
        public string Address { get; set; } = "";
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public List<OrderItem> Items { get; set; } = new();
        public decimal Total { get; set; }
        public string Status { get; set; } = "Created";
    }
}