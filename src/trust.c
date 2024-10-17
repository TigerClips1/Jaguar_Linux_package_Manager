#include "ps4_defines.h"
#include "ps4_trust.h"
#include "ps4_io.h"

struct ps4_trust_key *ps4_trust_load_key(int dirfd, const char *filename, int priv)
{
	struct ps4_trust_key *key;
	int r;

	key = calloc(1, sizeof *key);
	if (!key) return ERR_PTR(-ENOMEM);

	r = ps4_pkey_load(&key->key, dirfd, filename, priv);
	if (r) {
		free(key);
		return ERR_PTR(r);
	}

	list_init(&key->key_node);
	key->filename = strdup(filename);
	return key;
}

static int __ps4_trust_load_pubkey(void *pctx, int dirfd, const char *filename)
{
	struct ps4_trust *trust = pctx;
	struct ps4_trust_key *key = ps4_trust_load_key(dirfd, filename, 0);

	if (!IS_ERR(key))
		list_add_tail(&key->key_node, &trust->trusted_key_list);

	return 0;
}

void ps4_trust_init(struct ps4_trust *trust)
{
	*trust = (struct ps4_trust){};
	ps4_digest_ctx_init(&trust->dctx, PS4_DIGEST_NONE);
	list_init(&trust->trusted_key_list);
	list_init(&trust->private_key_list);
}

int ps4_trust_load_keys(struct ps4_trust *trust, int dirfd)
{
	if (!trust->keys_loaded) {
		trust->keys_loaded = 1;
		ps4_dir_foreach_file(dirfd, __ps4_trust_load_pubkey, trust);
	}

	return 0;
}

static void __ps4_trust_free_keys(struct list_head *h)
{
	struct ps4_trust_key *tkey, *n;

	list_for_each_entry_safe(tkey, n, h, key_node) {
		list_del(&tkey->key_node);
		ps4_pkey_free(&tkey->key);
		free(tkey->filename);
		free(tkey);
	}
}

void ps4_trust_free(struct ps4_trust *trust)
{
	__ps4_trust_free_keys(&trust->trusted_key_list);
	__ps4_trust_free_keys(&trust->private_key_list);
	ps4_digest_ctx_free(&trust->dctx);
}

struct ps4_pkey *ps4_trust_key_by_name(struct ps4_trust *trust, const char *filename)
{
	struct ps4_trust_key *tkey;

	list_for_each_entry(tkey, &trust->trusted_key_list, key_node)
		if (tkey->filename && strcmp(tkey->filename, filename) == 0)
			return &tkey->key;
	return NULL;
}
