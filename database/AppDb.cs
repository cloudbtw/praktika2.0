using Microsoft.EntityFrameworkCore;
using SneakerShop.Models;
using System.Security.Cryptography;
using System.Text;

namespace WebApplication10.database
{
    public class AppDb : DbContext
    {
        public AppDb(DbContextOptions<AppDb> opts) : base(opts) { }

        public DbSet<User> Users => Set<User>();
        public DbSet<Sneaker> Sneakers => Set<Sneaker>();
        public DbSet<CartItem> Cart => Set<CartItem>();
        public DbSet<Review> Reviews => Set<Review>();
        public DbSet<Order> Orders => Set<Order>();
        public DbSet<OrderItem> OrderItems => Set<OrderItem>();

        public void Seed()
        {
            if (Sneakers.Any()) return;

            var baseModels = new List<(string name, string color, decimal basePrice, bool delivery)>
            {
                ("AirLite","White",79.99m,true),
                ("RunnerX","Black",99.50m,true),
                ("StreetPro","Red",69.00m,false),
                ("Zoomer","Blue",129.99m,true),
                ("FlexOne","Green",59.99m,true),
                ("Sprint","Grey",89.99m,false),
                ("Cloud9","White",119.99m,true),
                ("Urban","Black",74.99m,true),
                ("Trail","Brown",139.99m,false),
                ("Classic","Beige",49.99m,true),
                ("Neo","Yellow",109.99m,true),
                ("Volt","Orange",95.00m,false),
                ("Comet","Navy",85.00m,true),
                ("Glide","Silver",115.00m,true),
                ("Pulse","Maroon",92.50m,false)
            };

            var rnd = new Random(42);
            foreach (var m in baseModels)
            {
                for (int size = 36; size <= 45; size++)
                {
                    Sneakers.Add(new Sneaker
                    {
                        Name = m.name,
                        Size = size,
                        Color = m.color,
                        Stock = rnd.Next(0, 12),
                        Price = Math.Round(m.basePrice + (decimal)(rnd.NextDouble() * 30 - 10), 2),
                        Delivery = m.delivery
                    });
                }
            }

            Users.AddRange(new[]
            {
                new User{Login="director", PasswordHash=Hash("dirpass"), Role="Director"},
                new User{Login="worker", PasswordHash=Hash("workpass"), Role="Worker"},
                new User{Login="buyer", PasswordHash=Hash("buy1"), Role="Buyer"}
            });

            SaveChanges();
        }

        public static string Hash(string input)
        {
            using var sha = SHA256.Create();
            var bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(input));
            return Convert.ToHexString(bytes);
        }
    }
}