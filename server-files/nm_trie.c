#include "../common.h"
#include "nameserver.h"
#include <sys/time.h>
#include <signal.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <netinet/tcp.h>
#include <unistd.h>


TrieNode *create_trie_node()
{
    TrieNode *node = (TrieNode *)calloc(1, sizeof(TrieNode));
    node->ss_index = -1;
    node->is_end = 0;
    return node;
}

void trie_insert(TrieNode *root, const char *key, int ss_idx)
{
    TrieNode *curr = root;
    for (int i = 0; key[i]; i++)
    {
        unsigned char ch = (unsigned char)key[i];
        if (!curr->children[ch])
        {
            curr->children[ch] = create_trie_node();
        }
        curr = curr->children[ch];
    }
    curr->is_end = 1;
    curr->ss_index = ss_idx;
}

int trie_search(TrieNode *root, const char *key)
{
    TrieNode *curr = root;
    for (int i = 0; key[i]; i++)
    {
        unsigned char ch = (unsigned char)key[i];
        if (!curr->children[ch])
            return -1;
        curr = curr->children[ch];
    }
    return (curr && curr->is_end) ? curr->ss_index : -1;
}

// Mark a given key as deleted in the trie (non-destructive; leaves nodes allocated)
void trie_delete(TrieNode *root, const char *key)
{
    if (!root || !key)
        return;
    TrieNode *curr = root;
    for (int i = 0; key[i]; i++)
    {
        unsigned char ch = (unsigned char)key[i];
        if (!curr->children[ch])
            return; // key not present
        curr = curr->children[ch];
    }
    if (curr)
    {
        curr->is_end = 0;
        curr->ss_index = -1;
    }
}
