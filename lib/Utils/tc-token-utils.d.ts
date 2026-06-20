import type { SignalKeyStore, SignalKeyStoreWithTransaction } from '../Types/index.js';
import { type BinaryNode } from '../WABinary/index.js';
/**
 * Check if a tctoken has expired based on the rolling bucket algorithm.
 * Tokens older than (NUM_BUCKETS - 1) bucket durations are considered expired.
 */
export declare function isTcTokenExpired(timestamp: number | string | null | undefined): boolean;
/**
 * Determine if a new tctoken should be sent to a contact.
 * Returns true if the senderTimestamp has crossed into a new bucket,
 * indicating it's time to re-issue the token.
 */
export declare function shouldSendNewTcToken(senderTimestamp: number | undefined): boolean;
/**
 * Resolve a JID to its LID for tctoken storage.
 * Mirrors Signal session key patterns — tctokens are stored/looked up by LID.
 */
export declare function resolveTcTokenJid(jid: string, getLIDForPN: (pn: string) => Promise<string | null>): Promise<string>;
type TcTokenParams = {
    jid: string;
    baseContent?: BinaryNode[];
    authState: {
        keys: SignalKeyStoreWithTransaction;
    };
    /** Optional LID resolver — when provided, storage key will be resolved to LID */
    getLIDForPN?: (pn: string) => Promise<string | null>;
};
/**
 * Builds tctoken binary nodes from a JID.
 * Useful for profile picture and presence subscription requests.
 * When getLIDForPN is provided, resolves the JID to LID for storage lookup
 * and performs opportunistic cleanup of expired tokens.
 */
export declare function buildTcTokenFromJid({ authState, jid, baseContent, getLIDForPN }: TcTokenParams): Promise<BinaryNode[] | undefined>;
export type StoreTcTokensParams = {
    result: BinaryNode;
    fallbackJid: string;
    keys: SignalKeyStore | SignalKeyStoreWithTransaction;
    getLIDForPN: (pn: string) => Promise<string | null>;
    /** Called when a new JID is stored for the first time (for index tracking) */
    onNewJidStored?: (jid: string) => void;
};
/**
 * Parse tctoken(s) from an IQ result and store them.
 * Includes a timestamp monotonicity guard to prevent older tokens from overwriting newer ones.
 */
export declare function storeTcTokensFromIqResult({ result, fallbackJid, keys, getLIDForPN, onNewJidStored }: StoreTcTokensParams): Promise<void>;
export {};
//# sourceMappingURL=tc-token-utils.d.ts.map