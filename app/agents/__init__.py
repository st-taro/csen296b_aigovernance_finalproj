"""Specialized agents. Importing this package registers every agent on the bus
and every tool with the gateway."""
from app import bus
from app.agents import email_agent, intake, records, refunds, reporting

ALL = [intake.AGENT, email_agent.AGENT, records.AGENT, refunds.AGENT, reporting.AGENT]
for _a in ALL:
    bus.register_agent(_a)


def describe() -> list:
    return [{"name": a.name, "description": a.description, "tools": bus.list_tools(a.name)} for a in ALL]
