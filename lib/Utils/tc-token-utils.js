import { getBinaryNodeChild, getBinaryNodeChildren, isLidUser, jidNormalizedUser } from '../WABinary/index.js';
/** 7 days in seconds — matches WA Web tctoken_duration */
const TC_TOKEN_BUCKET_DURATION = 604800;
/** 4 buckets — matches WA Web tctoken_num_buckets */
const TC_TOKEN_NUM_BUCKETS = 4;
/**
 * Check if a tctoken has expired based on the rolling bucket algorithm.
 * Tokens older than (NUM_BUCKETS - 1) bucket durations are considered expired.
 */
export function isTcTokenExpired(timestamp) {
    if (timestamp === null || timestamp === undefined)
        return true;
    const ts = typeof timestamp === 'string' ? parseInt(timestamp) : timestamp;
    if (isNaN(ts))
        return true;
    const now = Math.floor(Date.now() / 1000);
    const currentBucket = Math.floor(now / TC_TOKEN_BUCKET_DURATION);
    const cutoffBucket = currentBucket - (TC_TOKEN_NUM_BUCKETS - 1);
    const cutoffTimestamp = cutoffBucket * TC_TOKEN_BUCKET_DURATION;
    return ts < cutoffTimestamp;
}
/**
 * Determine if a new tctoken should be sent to a contact.
 * Returns true if the senderTimestamp has crossed into a new bucket,
 * indicating it's time to re-issue the token.
 */
export function shouldSendNewTcToken(senderTimestamp) {
    if (senderTimestamp === undefined)
        return true;
    const now = Math.floor(Date.now() / 1000);
    const currentBucket = Math.floor(now / TC_TOKEN_BUCKET_DURATION);
    const senderBucket = Math.floor(senderTimestamp / TC_TOKEN_BUCKET_DURATION);
    return currentBucket > senderBucket;
}
/**
 * Resolve a JID to its LID for tctoken storage.
 * Mirrors Signal session key patterns — tctokens are stored/looked up by LID.
 */
export async function resolveTcTokenJid(jid, getLIDForPN) {
    if (isLidUser(jid))
        return jid;
    const lid = await getLIDForPN(jid);
    return lid ?? jid;
}
/**
 * Builds tctoken binary nodes from a JID.
 * Useful for profile picture and presence subscription requests.
 * When getLIDForPN is provided, resolves the JID to LID for storage lookup
 * and performs opportunistic cleanup of expired tokens.
 */
export async function buildTcTokenFromJid({ authState, jid, baseContent = [], getLIDForPN }) {
    try {
        const storageJid = getLIDForPN
            ? await resolveTcTokenJid(jid, getLIDForPN)
            : jid;
        const tcTokenData = await authState.keys.get('tctoken', [storageJid]);
        const entry = tcTokenData?.[storageJid];
        let tcTokenBuffer = entry?.token;
        // Treat expired tokens the same as missing
        if (tcTokenBuffer?.length && isTcTokenExpired(entry?.timestamp)) {
            tcTokenBuffer = undefined;
            // Opportunistic cleanup: remove expired token from store
            try {
                await authState.keys.set({ tctoken: { [storageJid]: null } });
            }
            catch { /* ignore cleanup errors */ }
        }
        if (!tcTokenBuffer) {
            return baseContent.length > 0 ? baseContent : undefined;
        }
        baseContent.push({
            tag: 'tctoken',
            attrs: {},
            content: tcTokenBuffer
        });
        return baseContent;
    }
    catch {
        return baseContent.length > 0 ? baseContent : undefined;
    }
}
/**
 * Parse tctoken(s) from an IQ result and store them.
 * Includes a timestamp monotonicity guard to prevent older tokens from overwriting newer ones.
 */
export async function storeTcTokensFromIqResult({ result, fallbackJid, keys, getLIDForPN, onNewJidStored }) {
    const tokensNode = getBinaryNodeChild(result, 'tokens');
    if (!tokensNode)
        return;
    const tokenNodes = getBinaryNodeChildren(tokensNode, 'token');
    for (const tokenNode of tokenNodes) {
        if (tokenNode.attrs.type !== 'trusted_contact' || !(tokenNode.content instanceof Uint8Array)) {
            continue;
        }
        const rawJid = jidNormalizedUser(tokenNode.attrs.jid || fallbackJid);
        const storageJid = await resolveTcTokenJid(rawJid, getLIDForPN);
        const existingTcData = await keys.get('tctoken', [storageJid]);
        const existingEntry = existingTcData[storageJid];
        // Timestamp monotonicity guard — only store if incoming timestamp >= existing
        const existingTs = existingEntry?.timestamp ? Number(existingEntry.timestamp) : 0;
        const incomingTs = tokenNode.attrs.t ? Number(tokenNode.attrs.t) : 0;
        if (existingTs > 0 && incomingTs > 0 && existingTs > incomingTs) {
            continue;
        }
        await keys.set({
            tctoken: {
                [storageJid]: {
                    ...existingEntry,
                    token: Buffer.from(tokenNode.content),
                    timestamp: tokenNode.attrs.t
                }
            }
        });
        onNewJidStored?.(storageJid);
    }
}
//# sourceMappingURL=tc-token-utils.js.map