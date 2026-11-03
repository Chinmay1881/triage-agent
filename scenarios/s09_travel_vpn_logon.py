"""s09 (benign): an employee who regularly works from Ireland logs on to the VPN from there
over the weekend, through the company's own Dublin VPN point of presence, with MFA.
The alert ("first logon from IE in 30 days") is technically true: all their logons this
week came from GB. What makes it benign: IE is in the directory's usual_countries, MFA
succeeded, and the source IP is the corporate egress listed known_good in intel.

VPN-01 is shared with s03. s09 goes on a weekend day, at least 30 hours after s03's
weeknight spray, so no 24 h tool window can contain both.
"""

from scripts.gen.core import World, at, day, secs
from scripts.gen.infra import CORPORATE_VPN_EGRESS
from scripts.gen.scenario import AlertDraft, Context, ScenarioResult

SCENARIO_ID = "s09"
VPN_GATEWAY = "VPN-01"
COUNTRY = "IE"
WEEKEND = [5, 6]


def _active_on(world: World, user: str, day_index: int) -> bool:
    date = day(day_index).date()
    return any(d.user == user and d.ts.date() == date for d in world.drafts)


def inject(ctx: Context) -> ScenarioResult:
    w, rng = ctx.world, ctx.rng
    travellers = sorted(
        u.username
        for u in w.users
        if COUNTRY in u.usual_countries
        and not u.is_service_account
        and u.username not in ctx.claims.users
    )
    # A day with no background activity for them, so nothing places them in GB that day.
    options = [(u, d) for u in travellers for d in WEEKEND if not _active_on(w, u, d)]
    if not options:
        raise RuntimeError("s09 needs an unclaimed user with IE in usual_countries")
    user, d = rng.choice(options)
    t = at(d, 11) + secs(rng.randrange(4 * 3600))

    first = w.logon(t, VPN_GATEWAY, user, "vpn", CORPORATE_VPN_EGRESS, COUNTRY, mfa=True)
    later = t + secs(rng.randint(2 * 3600, 4 * 3600))
    second = w.logon(later, VPN_GATEWAY, user, "vpn", CORPORATE_VPN_EGRESS, COUNTRY, mfa=True)

    return ScenarioResult(
        scenario_id=SCENARIO_ID,
        title="Employee travelling, logs in from abroad on VPN with MFA",
        verdict="benign",
        expected_techniques=[],
        events=ctx.emitted(),
        key_events=[first, second],
        alert=AlertDraft(
            ts=first.ts + secs(5),
            rule="Login from new country",
            severity="medium",
            host=VPN_GATEWAY,
            user=user,
            description=f"First logon from {COUNTRY} for this account in 30 days.",
            triggers=[first],
        ),
        indicators=[],
    )
