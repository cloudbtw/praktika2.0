using Microsoft.AspNetCore.SignalR;

namespace WebApplication10.hub
{
    public class ShopHub : Hub
    {
        public Task NotifyCatalog() => Clients.All.SendAsync("CatalogUpdated");
        public Task NotifyCart(int userId) => Clients.All.SendAsync("CartUpdated", userId);
    }
}