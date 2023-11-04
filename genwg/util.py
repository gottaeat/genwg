def gen_wg_priv():
    return (
        subprocess.run(["wg", "genkey"], check=True, capture_output=True)
        .stdout.decode("utf-8")
        .rstrip("\n")
    )


def gen_wg_pub(priv_key):
    return (
        subprocess.run(
            ["wg", "pubkey"], input=priv_key, check=True, capture_output=True
        )
        .stdout.decode("utf-8")
        .rstrip("\n")
    )
