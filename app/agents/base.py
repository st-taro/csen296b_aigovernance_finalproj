from app import bus, gateway


class Agent:
    """A specialized agent. It owns a set of gateway tools and receives
    MCP-style tools/call messages over the bus. When it needs another agent
    it sends a message through the bus rather than calling it directly."""
    name = "base"
    description = ""

    def handle(self, tool: str, args: dict, ctx: gateway.Ctx):
        # The agent acts under its own identity; the gateway decides.
        return gateway.call(self.name, tool, args, ctx)

    def ask(self, recipient: str, tool: str, args: dict, ctx: gateway.Ctx):
        return bus.send(self.name, recipient, tool, args, ctx)
