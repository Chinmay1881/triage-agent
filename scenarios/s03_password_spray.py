"""s03: overnight password spray against the VPN, one attempt per account, until one
account without MFA enforcement logs in. Story: ~15 real accounts plus a few guessed names
fail from one address over ~20 minutes, then one of the real accounts succeeds with mfa=false
(its normal VPN logons always use MFA) and reconnects a few minutes later."""

from scripts.gen.core import at, secs
from scripts.gen.scenario import AlertDraft, Context, Indicator, ScenarioResult

SCENARIO_ID = "s03"
GUESSED_NAMES = ["administrator", "test", "scanner", "backup"]
COUNTRIES = ["NL", "RO", "BR", "VN"]
ALERT_THRESHOLD = 10


def inject(ctx: Context) -> ScenarioResult:
    w, rng = ctx.world, ctx.rng
    gateway = ctx.pick(["VPN-01"])
    ip = ctx.bad_ip(1)
    country = COUNTRIES[(ctx.variant - 1) % len(COUNTRIES)]
    people = sorted(
        u.username
        for u in w.users
        if not u.is_service_account and u.username not in ctx.claims.users
    )
    # The victim hot-desks, so their normal VPN logons (always with MFA) are in the
    # background for contrast with the attacker's mfa=false logon.
    hot_deskers = {u for users in w.desk_users.values() if len(users) > 1 for u in users}
    victim = rng.choice([p for p in people if p in hot_deskers])
    others = rng.sample([p for p in people if p != victim], k=14)
    attempts = rng.sample(others + GUESSED_NAMES, k=len(others) + len(GUESSED_NAMES))
    d = rng.choice([1, 2, 3])

    t = at(d, 1) + secs(rng.randrange(2 * 3600))
    failures = []
    for name in attempts:
        reason = "unknown_user" if name in GUESSED_NAMES else "bad_password"
        failures.append(
            w.logon(t, gateway, name, "vpn", ip, country, result="failure", failure_reason=reason)
        )
        t += secs(rng.randint(40, 90))
    success = w.logon(t, gateway, victim, "vpn", ip, country)
    reconnect = w.logon(t + secs(rng.randint(240, 600)), gateway, victim, "vpn", ip, country)

    return ScenarioResult(
        scenario_id=SCENARIO_ID,
        title="Password spraying, then one account logs in",
        verdict="malicious",
        expected_techniques=["T1110.003", "T1078"],
        events=ctx.emitted(),
        key_events=[*failures, success, reconnect],
        alert=AlertDraft(
            ts=failures[ALERT_THRESHOLD - 1].ts + secs(5),
            rule="Many failed logons across accounts",
            severity="medium",
            host=gateway,
            user=None,
            description=f"{ALERT_THRESHOLD} accounts failed VPN logon from one source in 15 min.",
            triggers=failures[:ALERT_THRESHOLD],
        ),
        indicators=[Indicator(ip, "ip", False, "Password spraying source")],
    )
