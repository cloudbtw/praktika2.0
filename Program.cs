using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.SignalR;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);
var jwtKey = "super-secret-key-12345";
builder.Services.AddDbContext<AppDb>(opt => opt.UseInMemoryDatabase("shopdb"));
builder.Services.AddSignalR();
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey))
        };
        options.Events = new JwtBearerEvents
        {
            OnMessageReceived = ctx =>
            {
                var accessToken = ctx.Request.Query["access_token"].FirstOrDefault();
                var path = ctx.HttpContext.Request.Path;
                if (!string.IsNullOrEmpty(accessToken) && path.StartsWithSegments("/hub"))
                {
                    ctx.Token = accessToken;
                }
                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthorization();
builder.Services.AddCors(opt =>
    opt.AddDefaultPolicy(p => p.AllowAnyHeader().AllowAnyMethod().AllowAnyOrigin()));

var app = builder.Build();
app.UseCors();
app.UseAuthentication();
app.UseAuthorization();
app.UseDefaultFiles();
app.UseStaticFiles();
app.MapHub<ShopHub>("/hub");
string CreateToken(User u)
{
    var claims = new List<Claim>
    {
        new Claim(ClaimTypes.Name, u.Login),
        new Claim(ClaimTypes.NameIdentifier, u.Id.ToString()),
        new Claim(ClaimTypes.Role, u.Role)
    };
    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
    var token = new JwtSecurityToken(claims: claims, expires: DateTime.UtcNow.AddHours(6), signingCredentials: creds);
    return new JwtSecurityTokenHandler().WriteToken(token);
}
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDb>();
    db.Database.EnsureCreated();
    db.Seed();
}
app.MapPost("/api/register", async (HttpContext context, AppDb db) =>
{
    try
    {
        context.Request.EnableBuffering();
using var reader = new StreamReader(context.Request.Body, Encoding.UTF8, leaveOpen: true);
        var requestBody = await reader.ReadToEndAsync();
        context.Request.Body.Position = 0;

        Console.WriteLine($"Registration request body: {requestBody}");

        if (string.IsNullOrWhiteSpace(requestBody))
        {
            return Results.BadRequest("Пустой запрос");
        }
        JsonElement jsonElement;
        try
        {
            jsonElement = JsonSerializer.Deserialize<JsonElement>(requestBody);
        }
        catch (JsonException)
        {
            return Results.BadRequest("Неверный формат JSON");
        }
        string? login = null;
        string? password = null;
        string? role = null;

        if (jsonElement.TryGetProperty("login", out var loginProp) && loginProp.ValueKind == JsonValueKind.String)
            login = loginProp.GetString();
                if (jsonElement.TryGetProperty("password", out var passwordProp) && passwordProp.ValueKind == JsonValueKind.String)
            password = passwordProp.GetString();
        if (jsonElement.TryGetProperty("role", out var roleProp) && roleProp.ValueKind == JsonValueKind.String)
            role = roleProp.GetString();
        if (string.IsNullOrWhiteSpace(login))
            return Results.BadRequest("Логин обязателен");

        if (string.IsNullOrWhiteSpace(password))
            return Results.BadRequest("Пароль обязателен");
        if (await db.Users.AnyAsync(u => u.Login == login))
            return Results.Conflict("Пользователь уже существует");
        var user = new User
        {
            Login = login.Trim(),
            PasswordHash = AppDb.Hash(password),
            Role = string.IsNullOrWhiteSpace(role) ? "Buyer" : role.Trim()
        };

        db.Users.Add(user);
        await db.SaveChangesAsync();

        Console.WriteLine($"User registered: {user.Login}, Role: {user.Role}");

        return Results.Ok(new
        {
            message = "Регистрация успешна",
            userId = user.Id,
            login = user.Login,
            role = user.Role
        });
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Registration error: {ex.Message}");
        Console.WriteLine($"Stack trace: {ex.StackTrace}");
        return Results.Problem("Внутренняя ошибка сервера");
    }
});
app.MapPost("/api/login", async (HttpContext context, AppDb db) =>
{
    try
    {
        context.Request.EnableBuffering();

        using var reader = new StreamReader(context.Request.Body, Encoding.UTF8, leaveOpen: true);
        var requestBody = await reader.ReadToEndAsync();
        context.Request.Body.Position = 0;

        Console.WriteLine($"Login request body: {requestBody}");

        if (string.IsNullOrWhiteSpace(requestBody))
            return Results.BadRequest("Пустой запрос");

        JsonElement jsonElement;
        try
        {
            jsonElement = JsonSerializer.Deserialize<JsonElement>(requestBody);
        }
        catch (JsonException)
        {
            return Results.BadRequest("Неверный формат JSON");
        }

        string? login = null;
        string? password = null;

        if (jsonElement.TryGetProperty("login", out var loginProp) && loginProp.ValueKind == JsonValueKind.String)
            login = loginProp.GetString();

        if (jsonElement.TryGetProperty("password", out var passwordProp) && passwordProp.ValueKind == JsonValueKind.String)
            password = passwordProp.GetString();

        if (string.IsNullOrWhiteSpace(login) || string.IsNullOrWhiteSpace(password))
            return Results.BadRequest("Логин и пароль обязательны");

        var hash = AppDb.Hash(password);
        var user = await db.Users
            .FirstOrDefaultAsync(u => u.Login == login && u.PasswordHash == hash);

        if (user == null)
            return Results.Unauthorized();

        var token = CreateToken(user);

        Console.WriteLine($"User logged in: {user.Login}, Role: {user.Role}");

        return Results.Ok(new
        {
            token,
            role = user.Role,
            login = user.Login,
            userId = user.Id
        });
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Login error: {ex.Message}");
        return Results.Problem("Внутренняя ошибка сервера");
    }
});
app.MapGet("/api/sneakers", async (AppDb db, string? q, int? size, string? color, string? sort) =>
{
    var query = db.Sneakers.AsQueryable();
    if (!string.IsNullOrWhiteSpace(q)) query = query.Where(s => s.Name.ToLower().Contains(q.ToLower()));
    if (size.HasValue) query = query.Where(s => s.Size == size.Value);
    if (!string.IsNullOrWhiteSpace(color)) query = query.Where(s => s.Color.ToLower() == color.ToLower());
    query = sort?.ToLower() switch
    {
        "price" => query.OrderBy(s => s.Price),
        "price_desc" => query.OrderByDescending(s => s.Price),
        "name" => query.OrderBy(s => s.Name),
        "stock" => query.OrderByDescending(s => s.Stock),
        _ => query.OrderBy(s => s.Name)
    };
    var list = await query.ToListAsync();
    return Results.Ok(list);
});

app.MapGet("/api/sneakers/filters", async (AppDb db) =>
{
    var sizes = await db.Sneakers.Select(s => s.Size).Distinct().OrderBy(x => x).ToListAsync();
    var colors = await db.Sneakers.Select(s => s.Color).Distinct().OrderBy(x => x).ToListAsync();
    return Results.Ok(new { sizes, colors });
});

app.MapGet("/api/sneakers/{id:int}", async (int id, AppDb db) =>
{
    var s = await db.Sneakers.FindAsync(id);
    return s is null ? Results.NotFound() : Results.Ok(s);
});

app.MapPost("/api/sneakers", [Authorize(Roles = "Worker,Director")] async (Sneaker s, AppDb db, IHubContext<ShopHub> hub) =>
{
    db.Sneakers.Add(s);
    await db.SaveChangesAsync();
    await hub.Clients.All.SendAsync("CatalogUpdated");
    return Results.Created($"/api/sneakers/{s.Id}", s);
});

app.MapPut("/api/sneakers/{id:int}", [Authorize(Roles = "Worker,Director")] async (int id, Sneaker input, AppDb db, IHubContext<ShopHub> hub) =>
{
    var s = await db.Sneakers.FindAsync(id);
    if (s == null) return Results.NotFound();
    s.Name = input.Name; s.Size = input.Size; s.Color = input.Color; s.Stock = input.Stock; s.Price = input.Price; s.Delivery = input.Delivery;
    await db.SaveChangesAsync();
    await hub.Clients.All.SendAsync("CatalogUpdated");
    return Results.Ok(s);
});

app.MapDelete("/api/sneakers/{id:int}", [Authorize(Roles = "Worker,Director")] async (int id, AppDb db, IHubContext<ShopHub> hub) =>
{
    var s = await db.Sneakers.FindAsync(id);
    if (s == null) return Results.NotFound();
    db.Sneakers.Remove(s);
    await db.SaveChangesAsync();
    await hub.Clients.All.SendAsync("CatalogUpdated");
    return Results.Ok();
});

app.MapPost("/api/sneakers/{id:int}/restock", [Authorize(Roles = "Worker,Director")] async (int id, RestockDto dto, AppDb db, IHubContext<ShopHub> hub) =>
{
    var s = await db.Sneakers.FindAsync(id);
    if (s == null) return Results.NotFound();
    s.Stock += dto.Amount;
    await db.SaveChangesAsync();
    await hub.Clients.All.SendAsync("CatalogUpdated");
    return Results.Ok(s);
});

app.MapGet("/api/me", [Authorize] (ClaimsPrincipal user, AppDb db) =>
{
    var idClaim = user.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    if (!int.TryParse(idClaim, out var id)) return Results.Unauthorized();
    var u = db.Users.Find(id);
    if (u == null) return Results.NotFound();
    return Results.Ok(new { u.Id, u.Login, u.Role });
});

app.MapGet("/api/cart", [Authorize] async (ClaimsPrincipal user, AppDb db) =>
{
    var idClaim = user.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    if (!int.TryParse(idClaim, out var uid)) return Results.Unauthorized();
    var items = await db.Cart.Where(c => c.UserId == uid).ToListAsync();
    return Results.Ok(items);
});

app.MapPost("/api/cart", [Authorize] async (CartAddDto dto, ClaimsPrincipal user, AppDb db, IHubContext<ShopHub> hub) =>
{
    var idClaim = user.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    if (!int.TryParse(idClaim, out var uid)) return Results.Unauthorized();
    var sneaker = await db.Sneakers.FindAsync(dto.SneakerId);
    if (sneaker == null) return Results.NotFound("Sneaker not found");
    var existing = await db.Cart.FirstOrDefaultAsync(c => c.UserId == uid && c.SneakerId == dto.SneakerId);
    if (existing != null) existing.Qty += dto.Qty;
    else db.Cart.Add(new CartItem { UserId = uid, SneakerId = dto.SneakerId, Qty = dto.Qty });
    await db.SaveChangesAsync();
    await hub.Clients.All.SendAsync("CartUpdated", uid);
    return Results.Ok();
});

app.MapDelete("/api/cart/{id:int}", [Authorize] async (int id, ClaimsPrincipal user, AppDb db, IHubContext<ShopHub> hub) =>
{
    var idClaim = user.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    if (!int.TryParse(idClaim, out var uid)) return Results.Unauthorized();
    var item = await db.Cart.FindAsync(id);
    if (item == null || item.UserId != uid) return Results.NotFound();
    db.Cart.Remove(item);
    await db.SaveChangesAsync();
    await hub.Clients.All.SendAsync("CartUpdated", uid);
    return Results.Ok();
});

app.MapPost("/api/checkout", [Authorize] async (CheckoutDto dto, ClaimsPrincipal user, AppDb db, IHubContext<ShopHub> hub) =>
{
    var idClaim = user.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    if (!int.TryParse(idClaim, out var uid)) return Results.Unauthorized();

    var cartItems = await db.Cart.Where(c => c.UserId == uid).ToListAsync();
    if (!cartItems.Any()) return Results.BadRequest("Cart is empty");

    var sneakers = await db.Sneakers.Where(s => cartItems.Select(ci => ci.SneakerId).Contains(s.Id)).ToListAsync();
    foreach (var ci in cartItems)
    {
        var s = sneakers.FirstOrDefault(x => x.Id == ci.SneakerId);
        if (s == null) return Results.BadRequest($"Sneaker {ci.SneakerId} not found");
        if (s.Stock < ci.Qty) return Results.BadRequest($"Not enough stock for {s.Name} size {s.Size}");
    }

    var order = new Order { UserId = uid, Address = dto.Address ?? "", CreatedAt = DateTime.UtcNow, Status = "Created" };
    db.Orders.Add(order);
    await db.SaveChangesAsync();

    decimal total = 0;
    foreach (var ci in cartItems)
    {
        var s = sneakers.First(x => x.Id == ci.SneakerId);
        s.Stock -= ci.Qty;
        var oi = new OrderItem { OrderId = order.Id, SneakerId = s.Id, Qty = ci.Qty, Price = s.Price };
        db.OrderItems.Add(oi);
        order.Items.Add(oi);
        total += s.Price * ci.Qty;
    }
    order.Total = total;

    db.Cart.RemoveRange(cartItems);
    await db.SaveChangesAsync();

    await hub.Clients.All.SendAsync("CatalogUpdated");
    await hub.Clients.All.SendAsync("CartUpdated", uid);

    return Results.Ok(new { orderId = order.Id, total = order.Total });
});

app.MapGet("/api/orders", [Authorize] async (ClaimsPrincipal user, AppDb db) =>
{
    var idClaim = user.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    if (!int.TryParse(idClaim, out var uid)) return Results.Unauthorized();
    var orders = await db.Orders.Where(o => o.UserId == uid).Include(o => o.Items).ToListAsync();
    return Results.Ok(orders);
});

app.MapGet("/api/orders/all", [Authorize(Roles = "Director")] async (AppDb db) =>
{
    var orders = await db.Orders.Include(o => o.Items).ToListAsync();
    return Results.Ok(orders);
});

app.MapGet("/api/sneakers/{id:int}/reviews", async (int id, AppDb db) =>
{
    var r = await db.Reviews.Where(x => x.SneakerId == id).OrderByDescending(x => x.CreatedAt).ToListAsync();
    return Results.Ok(r);
});

app.MapPost("/api/sneakers/{id:int}/reviews", [Authorize] async (int id, ReviewDto dto, ClaimsPrincipal user, AppDb db, IHubContext<ShopHub> hub) =>
{
    var idClaim = user.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    if (!int.TryParse(idClaim, out var uid)) return Results.Unauthorized();
    var sneaker = await db.Sneakers.FindAsync(id);
    if (sneaker == null) return Results.NotFound();
    var rev = new Review { SneakerId = id, UserId = uid, Text = dto.Text, CreatedAt = DateTime.UtcNow };
    db.Reviews.Add(rev);
    await db.SaveChangesAsync();
    await hub.Clients.All.SendAsync("CatalogUpdated");
    return Results.Ok(rev);
});

app.MapGet("/api/users", [Authorize(Roles = "Director")] async (AppDb db) =>
{
    var users = await db.Users.Select(u => new { u.Id, u.Login, u.Role }).ToListAsync();
    return Results.Ok(users);
});
app.Run("http://localhost:5000");

//classes

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
        return BitConverter.ToString(bytes).Replace("-", "").ToLower();
    }
}

public class User
{
    public int Id { get; set; }
    public string Login { get; set; } = "";
    public string PasswordHash { get; set; } = "";
    public string Role { get; set; } = "Buyer";
}

public class Sneaker
{
    public int Id { get; set; }
    public string Name { get; set; } = "";
    public int Size { get; set; }
    public string Color { get; set; } = "";
    public int Stock { get; set; }
    public decimal Price { get; set; }
    public bool Delivery { get; set; }
}

public class CartItem
{
    public int Id { get; set; }
    public int UserId { get; set; }
    public int SneakerId { get; set; }
    public int Qty { get; set; }
}

public class Review
{
    public int Id { get; set; }
    public int SneakerId { get; set; }
    public int UserId { get; set; }
    public string Text { get; set; } = "";
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}

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

public class OrderItem
{
    public int Id { get; set; }
    public int OrderId { get; set; }
    public int SneakerId { get; set; }
    public int Qty { get; set; }
    public decimal Price { get; set; }
}

public class ShopHub : Hub
{
    public Task NotifyCatalog() => Clients.All.SendAsync("CatalogUpdated");
    public Task NotifyCart(int userId) => Clients.All.SendAsync("CartUpdated", userId);
}

//dto
public class UserRegisterDto
{
    public string? Login { get; set; }
    public string? Password { get; set; }
    public string? Role { get; set; }
}

public class UserLoginDto
{
    public string? Login { get; set; }
    public string? Password { get; set; }
}

public class CartAddDto
{
    public int SneakerId { get; set; }
    public int Qty { get; set; }
}

public class ReviewDto
{
    public string? Text { get; set; }
}

public class RestockDto
{
    public int Amount { get; set; }
}

public class CheckoutDto
{
    public string? Address { get; set; }
}
