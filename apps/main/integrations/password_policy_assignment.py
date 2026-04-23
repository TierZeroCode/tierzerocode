import logging

logger = logging.getLogger(__name__)


def assign_user_password_policies():
    """Assign PasswordPolicy FK to every UserData based on account type and FGPP.

    Rules:
    - Cloud-only (onPremisesSyncEnabled=False/None and no AD sync): Entra ID policy
    - Hybrid + FGPP assigned (ad_resultant_pso set):              matching AD FGPP
    - Hybrid + no FGPP:                                            None (default AD
                                                                   domain policy not
                                                                   yet implemented)

    Returns the number of rows updated.
    """
    from apps.main.models import PasswordPolicy, UserData

    entra_policy = PasswordPolicy.objects.filter(source='entra_id').first()

    fgpp_map = {
        p.policy_identifier: p
        for p in PasswordPolicy.objects.filter(source='active_directory')
    }

    to_update = []

    for user in UserData.objects.only(
        'id', 'onPremisesSyncEnabled', 'ad_synced_at',
        'ad_resultant_pso', 'password_policy_id',
    ).iterator(chunk_size=500):
        is_hybrid = bool(user.onPremisesSyncEnabled) or bool(user.ad_synced_at)

        if is_hybrid:
            pso_dn = user.ad_resultant_pso
            target = fgpp_map.get(pso_dn) if pso_dn else None
        else:
            target = entra_policy

        target_id = target.pk if target else None
        if user.password_policy_id != target_id:
            user.password_policy_id = target_id
            to_update.append(user)

    if to_update:
        UserData.objects.bulk_update(to_update, ['password_policy'])

    logger.info(
        "Password policy assignment complete: %d user(s) updated "
        "(entra_policy=%s, fgpp_policies=%d)",
        len(to_update),
        entra_policy.pk if entra_policy else None,
        len(fgpp_map),
    )
    return len(to_update)
