"""Human grants 100, shopping agent delegates 50; 25 allowed, 75 and 5000 denied."""

from pigeon import Principal, delegate, grant, verify

human = Principal.generate("human:alice", "human")
shopper = Principal.generate("agent:shopper", "agent")

budget = grant(
    subject=shopper,
    capabilities=["purchase"],
    resources=["merchant:*"],
    constraints={"amount": 100},
    issuer=human,
)

limited = delegate(
    budget,
    subject="agent:checkout",
    capabilities=["purchase"],
    resources=["merchant:books"],
    constraints={"amount": 50},
)

small = verify(limited, "purchase", "merchant:books", {"amount": 25})
over = verify(limited, "purchase", "merchant:books", {"amount": 75})
absurd = verify(limited, "purchase", "merchant:books", {"amount": 5000})

assert small.allowed
assert over.reason_code == "CONSTRAINT_VIOLATION"
assert absurd.reason_code == "CONSTRAINT_VIOLATION"
print("25:", "allowed")
print("75:", over.reason_code, over.details)
print("5000:", absurd.reason_code, absurd.details)
