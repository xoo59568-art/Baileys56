// @ts-ignore
import * as libsignal from 'libsignal';
// @ts-ignore
import { PreKeyWhisperMessage } from 'libsignal/src/protobufs.js';
import { LRUCache } from 'lru-cache';
import { BufferJSON, generateSignalPubKey } from '../Utils/index.js';
import { isHostedLidUser, isHostedPnUser, isLidUser, isPnUser, jidDecode, transferDevice, WAJIDDomains } from '../WABinary/index.js';
import { SenderKeyName } from './Group/sender-key-name.js';
import { SenderKeyRecord } from './Group/sender-key-record.js';
import { GroupCipher, GroupSessionBuilder, SenderKeyDistributionMessage } from './Group/index.js';
import { LIDMappingStore } from './lid-mapping.js';
/** Extract identity key from PreKeyWhisperMessage for identity change detection */
function extractIdentityFromPkmsg(ciphertext) {
    try {
        if (!ciphertext || ciphertext.length < 2) {
            return undefined;
        }
        // Version byte check (version 3)
        const version = ciphertext[0];
        if ((version & 0xf) !== 3) {
            return undefined;
        }
        // Parse protobuf (skip version byte)
        const preKeyProto = PreKeyWhisperMessage.decode(ciphertext.slice(1));
        if (preKeyProto.identityKey?.length === 33) {
            return new Uint8Array(preKeyProto.identityKey);
        }
        return undefined;
    }
    catch {
        return undefined;
    }
}
export function makeLibSignalRepository(auth, logger, pnToLIDFunc) {
    const lidMapping = new LIDMappingStore(auth.keys, logger, pnToLIDFunc);
    const storage = signalStorage(auth, lidMapping, logger);
    const parsedKeys = auth.keys;
    const migratedSessionCache = new LRUCache({
        ttl: 3 * 24 * 60 * 60 * 1000, // 7 days
        ttlAutopurge: true,
        updateAgeOnGet: true
    });
    const repository = {
        decryptGroupMessage({ group, authorJid, msg }) {
            const senderName = jidToSignalSenderKeyName(group, authorJid);
            const cipher = new GroupCipher(storage, senderName);
            // Use transaction to ensure atomicity
            return parsedKeys.transaction(async () => {
                return await cipher.decrypt(msg);
            }, group);
        },
        async processSenderKeyDistributionMessage({ item, authorJid }) {
            const builder = new GroupSessionBuilder(storage);
            if (!item.groupId) {
                throw new Error('Group ID is required for sender key distribution message');
            }
            const senderName = jidToSignalSenderKeyName(item.groupId, authorJid);
            const senderMsg = new SenderKeyDistributionMessage(null, null, null, null, item.axolotlSenderKeyDistributionMessage);
            const senderNameStr = senderName.toString();
            const { [senderNameStr]: senderKey } = await auth.keys.get('sender-key', [senderNameStr]);
            if (!senderKey) {
                await storage.storeSenderKey(senderName, new SenderKeyRecord());
            }
            return parsedKeys.transaction(async () => {
                const { [senderNameStr]: senderKey } = await auth.keys.get('sender-key', [senderNameStr]);
                if (!senderKey) {
                    await storage.storeSenderKey(senderName, new SenderKeyRecord());
                }
                await builder.process(senderName, senderMsg);
            }, item.groupId);
        },
        async decryptMessage({ jid, type, ciphertext }) {
            const addr = jidToSignalProtocolAddress(jid);
            const session = new libsignal.SessionCipher(storage, addr);
            // Extract and save sender's identity key before decryption for identity change detection
            if (type === 'pkmsg') {
                const identityKey = extractIdentityFromPkmsg(ciphertext);
                if (identityKey) {
                    const addrStr = addr.toString();
                    const identityChanged = await storage.saveIdentity(addrStr, identityKey);
                    if (identityChanged) {
                        logger.info({ jid, addr: addrStr }, 'identity key changed or new contact, session will be re-established');
                    }
                }
            }
            async function doDecrypt() {
                let result;
                switch (type) {
                    case 'pkmsg':
                        result = await session.decryptPreKeyWhisperMessage(ciphertext);
                        break;
                    case 'msg':
                        result = await session.decryptWhisperMessage(ciphertext);
                        break;
                }
                return result;
            }
            // If it's not a sync message, we need to ensure atomicity
            // For regular messages, we use a transaction to ensure atomicity
            return parsedKeys.transaction(async () => {
                return await doDecrypt();
            }, jid);
        },
        async encryptMessage({ jid, data }) {
            const addr = jidToSignalProtocolAddress(jid);
            const cipher = new libsignal.SessionCipher(storage, addr);
            // Use transaction to ensure atomicity
            return parsedKeys.transaction(async () => {
                const { type: sigType, body } = await cipher.encrypt(data);
                const type = sigType === 3 ? 'pkmsg' : 'msg';
                return { type, ciphertext: Buffer.from(body, 'binary') };
            }, jid);
        },
        async encryptGroupMessage({ group, meId, data }) {
            const senderName = jidToSignalSenderKeyName(group, meId);
            const builder = new GroupSessionBuilder(storage);
            const senderNameStr = senderName.toString();
            return parsedKeys.transaction(async () => {
                const { [senderNameStr]: senderKey } = await auth.keys.get('sender-key', [senderNameStr]);
                if (!senderKey) {
                    await storage.storeSenderKey(senderName, new SenderKeyRecord());
                }
                const senderKeyDistributionMessage = await builder.create(senderName);
                const session = new GroupCipher(storage, senderName);
                const ciphertext = await session.encrypt(data);
                return {
                    ciphertext,
                    senderKeyDistributionMessage: senderKeyDistributionMessage.serialize()
                };
            }, group);
        },
        async injectE2ESession({ jid, session }) {
            logger.trace({ jid }, 'injecting E2EE session');
            const cipher = new libsignal.SessionBuilder(storage, jidToSignalProtocolAddress(jid));
            return parsedKeys.transaction(async () => {
                await cipher.initOutgoing(session);
            }, jid);
        },
        jidToSignalProtocolAddress(jid) {
            return jidToSignalProtocolAddress(jid).toString();
        },
        // Optimized direct access to LID mapping store
        lidMapping,
        async validateSession(jid) {
            try {
                const addr = jidToSignalProtocolAddress(jid);
                const session = await storage.loadSession(addr.toString());
                if (!session) {
                    return { exists: false, reason: 'no session' };
                }
                if (!session.haveOpenSession()) {
                    return { exists: false, reason: 'no open session' };
                }
                return { exists: true };
            }
            catch (error) {
                return { exists: false, reason: 'validation error' };
            }
        },
        async validateSessions(jids) {
            if (!jids.length)
                return {};
            const uniqueJids = [...new Set(jids)];
            const addrStrings = [];
            const jidToAddr = {};
            for (const jid of uniqueJids) {
                const addr = jidToSignalProtocolAddress(jid).toString();
                addrStrings.push(addr);
                jidToAddr[jid] = addr;
            }
            // Shared resolution logic from signalStorage to get wire JIDs
            const resolveAddr = async (id) => {
                if (id.includes('.') && !id.includes('-')) {
                    const [deviceId, device] = id.split('.');
                    const [user, domainType_] = deviceId.split('_');
                    const domainType = parseInt(domainType_ || '0');
                    if (domainType === WAJIDDomains.LID || domainType === WAJIDDomains.HOSTED_LID)
                        return id;
                    const pnJid = `${user}${device !== '0' ? `:${device}` : ''}@${domainType === WAJIDDomains.HOSTED ? 'hosted' : 's.whatsapp.net'}`;
                    const lidForPN = await lidMapping.getLIDForPN(pnJid);
                    if (lidForPN) {
                        const lidAddr = jidToSignalProtocolAddress(lidForPN);
                        return lidAddr.toString();
                    }
                }
                return id;
            };
            const wireAddrStrings = await Promise.all(addrStrings.map(resolveAddr));
            const sessions = await parsedKeys.get('session', wireAddrStrings);
            const results = {};
            for (let i = 0; i < uniqueJids.length; i++) {
                const jid = uniqueJids[i];
                const wireAddr = wireAddrStrings[i];
                const sessionData = sessions[wireAddr];
                if (!sessionData) {
                    results[jid] = { exists: false, reason: 'no session' };
                }
                else {
                    try {
                        const session = libsignal.SessionRecord.deserialize(sessionData);
                        if (!session.haveOpenSession()) {
                            results[jid] = { exists: false, reason: 'no open session' };
                        }
                        else {
                            results[jid] = { exists: true };
                        }
                    }
                    catch (error) {
                        results[jid] = { exists: false, reason: 'deserialization error' };
                    }
                }
            }
            return results;
        },
        async deleteSession(jids) {
            if (!jids.length)
                return;
            // Convert JIDs to signal addresses and prepare for bulk deletion
            const sessionUpdates = {};
            for (const jid of jids) {
                const addr = jidToSignalProtocolAddress(jid).toString();
                sessionUpdates[addr] = null;
                // Also try to resolve LID if it's a PN
                if (isPnUser(jid)) {
                    const lid = await lidMapping.getLIDForPN(jid);
                    if (lid) {
                        // Preserve device part if present
                        const decoded = jidDecode(jid);
                        const lidWithDevice = decoded?.device
                            ? `${lid.split('@')[0]}:${decoded.device}@${lid.split('@')[1]}`
                            : lid;
                        const lidAddr = jidToSignalProtocolAddress(lidWithDevice).toString();
                        sessionUpdates[lidAddr] = null;
                    }
                }
            }
            // Single transaction for all deletions
            return parsedKeys.transaction(async () => {
                await auth.keys.set({ session: sessionUpdates });
            }, `delete-${jids.length}-sessions`);
        },
        async deleteIdentity(jids) {
            if (!jids.length)
                return;
            // Convert JIDs to signal addresses and prepare for bulk deletion
            const identityUpdates = {};
            for (const jid of jids) {
                const addr = jidToSignalProtocolAddress(jid).toString();
                identityUpdates[addr] = null;
                // Also try to resolve LID if it's a PN
                if (isPnUser(jid)) {
                    const lid = await lidMapping.getLIDForPN(jid);
                    if (lid) {
                        // Preserve device part if present
                        const decoded = jidDecode(jid);
                        const lidWithDevice = decoded?.device
                            ? `${lid.split('@')[0]}:${decoded.device}@${lid.split('@')[1]}`
                            : lid;
                        const lidAddr = jidToSignalProtocolAddress(lidWithDevice).toString();
                        identityUpdates[lidAddr] = null;
                    }
                }
            }
            // Single transaction for all deletions
            return parsedKeys.transaction(async () => {
                await auth.keys.set({ 'identity-key': identityUpdates });
            }, `delete-${jids.length}-identities`);
        },
        async migrateSession(fromJid, toJid) {
            // TODO: use usync to handle this entire mess
            if (!fromJid || (!isLidUser(toJid) && !isHostedLidUser(toJid)))
                return { migrated: 0, skipped: 0, total: 0 };
            // Only support PN to LID migration
            if (!isPnUser(fromJid) && !isHostedPnUser(fromJid)) {
                return { migrated: 0, skipped: 0, total: 1 };
            }
            const { user } = jidDecode(fromJid);
            logger.debug({ fromJid }, 'bulk device migration - loading all user devices');
            // Get user's device list from storage
            const { [user]: userDevices } = await parsedKeys.get('device-list', [user]);
            if (!userDevices) {
                return { migrated: 0, skipped: 0, total: 0 };
            }
            const { device: fromDevice } = jidDecode(fromJid);
            const fromDeviceStr = fromDevice?.toString() || '0';
            if (!userDevices.includes(fromDeviceStr)) {
                userDevices.push(fromDeviceStr);
            }
            // Filter out cached devices before database fetch
            const uncachedDevices = userDevices.filter(device => {
                const deviceKey = `${user}.${device}`;
                return !migratedSessionCache.has(deviceKey);
            });
            // Bulk check session existence only for uncached devices
            const deviceSessionKeys = uncachedDevices.map(device => `${user}.${device}`);
            const existingSessions = await parsedKeys.get('session', deviceSessionKeys);
            // Step 3: Convert existing sessions to JIDs (only migrate sessions that exist)
            const deviceJids = [];
            for (const [sessionKey, sessionData] of Object.entries(existingSessions)) {
                if (sessionData) {
                    // Session exists in storage
                    const deviceStr = sessionKey.split('.')[1];
                    if (!deviceStr)
                        continue;
                    const deviceNum = parseInt(deviceStr);
                    let jid = deviceNum === 0 ? `${user}@s.whatsapp.net` : `${user}:${deviceNum}@s.whatsapp.net`;
                    if (deviceNum === 99) {
                        jid = `${user}:99@hosted`;
                    }
                    deviceJids.push(jid);
                }
            }
            logger.debug({
                fromJid,
                totalDevices: userDevices.length,
                devicesWithSessions: deviceJids.length,
                devices: deviceJids
            }, 'bulk device migration complete - all user devices processed');
            // Single transaction for all migrations
            return parsedKeys.transaction(async () => {
                const migrationOps = deviceJids.map(jid => {
                    const lidWithDevice = transferDevice(jid, toJid);
                    const fromDecoded = jidDecode(jid);
                    const toDecoded = jidDecode(lidWithDevice);
                    return {
                        fromJid: jid,
                        toJid: lidWithDevice,
                        pnUser: fromDecoded.user,
                        lidUser: toDecoded.user,
                        deviceId: fromDecoded.device || 0,
                        fromAddr: jidToSignalProtocolAddress(jid),
                        toAddr: jidToSignalProtocolAddress(lidWithDevice)
                    };
                });
                const totalOps = migrationOps.length;
                let migratedCount = 0;
                // Bulk fetch PN sessions - already exist (verified during device discovery)
                const pnAddrStrings = Array.from(new Set(migrationOps.map(op => op.fromAddr.toString())));
                const pnSessions = await parsedKeys.get('session', pnAddrStrings);
                // Prepare bulk session updates (PN → LID migration + deletion)
                const sessionUpdates = {};
                for (const op of migrationOps) {
                    const pnAddrStr = op.fromAddr.toString();
                    const lidAddrStr = op.toAddr.toString();
                    const pnSession = pnSessions[pnAddrStr];
                    if (pnSession) {
                        // Session exists (guaranteed from device discovery)
                        const fromSession = libsignal.SessionRecord.deserialize(pnSession);
                        if (fromSession.haveOpenSession()) {
                            // Queue for bulk update: copy to LID, delete from PN
                            sessionUpdates[lidAddrStr] = fromSession.serialize();
                            sessionUpdates[pnAddrStr] = null;
                            migratedCount++;
                            // Also migrate identity keys
                            const { [pnAddrStr]: identityKey } = await parsedKeys.get('identity-key', [pnAddrStr]);
                            if (identityKey) {
                                sessionUpdates[`identity-key:${lidAddrStr}`] = identityKey;
                                sessionUpdates[`identity-key:${pnAddrStr}`] = null;
                                logger.debug({ pnAddrStr, lidAddrStr }, 'migrated identity key');
                            }
                            // Also migrate sender keys for common broadcats/groups if we have them
                            // This is an optimization to prevent decryption failures in groups after migration
                            // We prioritize status@broadcast but could expand to all groups if we knew them
                            const groupsToMigrate = ['status@broadcast'];
                            // If we have a target groupId (e.g. from context, though not passed here currently), we could add it
                            for (const groupId of groupsToMigrate) {
                                const pnSenderKeyName = new SenderKeyName(groupId, op.fromAddr).toString();
                                const lidSenderKeyName = new SenderKeyName(groupId, op.toAddr).toString();
                                const { [pnSenderKeyName]: senderKey } = await parsedKeys.get('sender-key', [
                                    pnSenderKeyName
                                ]);
                                if (senderKey) {
                                    sessionUpdates[`sender-key:${lidSenderKeyName}`] = senderKey;
                                    sessionUpdates[`sender-key:${pnSenderKeyName}`] = null;
                                }
                            }
                        }
                    }
                }
                // Single bulk session update for all migrations
                if (Object.keys(sessionUpdates).length > 0) {
                    const finalUpdates = { session: {}, 'sender-key': {}, 'identity-key': {} };
                    for (const [key, value] of Object.entries(sessionUpdates)) {
                        if (key.startsWith('sender-key:')) {
                            finalUpdates['sender-key'][key.split('sender-key:')[1]] = value;
                        }
                        else if (key.startsWith('identity-key:')) {
                            finalUpdates['identity-key'][key.split('identity-key:')[1]] = value;
                        }
                        else {
                            finalUpdates.session[key] = value;
                        }
                    }
                    await parsedKeys.set(finalUpdates);
                    logger.debug({ migratedSessions: migratedCount }, 'bulk session migration complete');
                    // Cache device-level migrations
                    for (const op of migrationOps) {
                        if (sessionUpdates[op.toAddr.toString()]) {
                            const deviceKey = `${op.pnUser}.${op.deviceId}`;
                            migratedSessionCache.set(deviceKey, true);
                        }
                    }
                }
                const skippedCount = totalOps - migratedCount;
                return { migrated: migratedCount, skipped: skippedCount, total: totalOps };
            }, `migrate-${deviceJids.length}-sessions-${jidDecode(toJid)?.user}`);
        }
    };
    return repository;
}
const jidToSignalProtocolAddress = (jid) => {
    const decoded = jidDecode(jid);
    const { user, device, server, domainType } = decoded;
    if (!user) {
        throw new Error(`JID decoded but user is empty: "${jid}" -> user: "${user}", server: "${server}", device: ${device}`);
    }
    const signalUser = domainType !== WAJIDDomains.WHATSAPP ? `${user}_${domainType}` : user;
    const finalDevice = device || 0;
    if (device === 99 && decoded.server !== 'hosted' && decoded.server !== 'hosted.lid') {
        throw new Error('Unexpected non-hosted device JID with device 99. This ID seems invalid. ID:' + jid);
    }
    return new libsignal.ProtocolAddress(signalUser, finalDevice);
};
const jidToSignalSenderKeyName = (group, user) => {
    return new SenderKeyName(group, jidToSignalProtocolAddress(user));
};
function signalStorage({ creds, keys }, lidMapping, logger) {
    // Shared function to resolve PN signal address to LID if mapping exists
    const resolveLIDSignalAddress = async (id) => {
        if (id.includes('.') && !id.includes('-')) {
            const [deviceId, device] = id.split('.');
            const [user, domainType_] = deviceId.split('_');
            const domainType = parseInt(domainType_ || '0');
            if (domainType === WAJIDDomains.LID || domainType === WAJIDDomains.HOSTED_LID)
                return id;
            const pnJid = `${user}${device !== '0' ? `:${device}` : ''}@${domainType === WAJIDDomains.HOSTED ? 'hosted' : 's.whatsapp.net'}`;
            const lidForPN = await lidMapping.getLIDForPN(pnJid);
            if (lidForPN) {
                const lidAddr = jidToSignalProtocolAddress(lidForPN);
                return lidAddr.toString();
            }
        }
        return id;
    };
    return {
        loadSession: async (id) => {
            try {
                const wireJid = await resolveLIDSignalAddress(id);
                const { [wireJid]: sess } = await keys.get('session', [wireJid]);
                if (sess) {
                    return libsignal.SessionRecord.deserialize(sess);
                }
            }
            catch (e) {
                return null;
            }
            return null;
        },
        storeSession: async (id, session) => {
            const wireJid = await resolveLIDSignalAddress(id);
            await keys.set({ session: { [wireJid]: session.serialize() } });
        },
        // @ts-ignore
        isTrustedIdentity: async (id, identityKey, direction) => {
            try {
                const wireJid = await resolveLIDSignalAddress(id);
                const { [wireJid]: storedKey } = await keys.get('identity-key', [wireJid]);
                if (storedKey) {
                    // Check if identity matches
                    if (Buffer.compare(storedKey, identityKey) !== 0) {
                        logger.info({ id, wireJid, direction }, 'identity changed, automatically updating trust');
                        await keys.set({
                            session: { [wireJid]: null },
                            'identity-key': { [wireJid]: identityKey }
                        });
                    }
                    return true;
                }
                // Trust on first use
                await keys.set({ 'identity-key': { [wireJid]: identityKey } });
                return true;
            }
            catch (e) {
                logger.error({ id, error: e }, 'failed to check trusted identity');
                return true; // fallback to trust on error
            }
        },
        loadIdentity: async (id) => {
            const wireJid = await resolveLIDSignalAddress(id);
            const { [wireJid]: key } = await keys.get('identity-key', [wireJid]);
            return key;
        },
        loadIdentityKey: async (id) => {
            const wireJid = await resolveLIDSignalAddress(id);
            const { [wireJid]: key } = await keys.get('identity-key', [wireJid]);
            return key || undefined;
        },
        saveIdentity: async (id, identityKey) => {
            const wireJid = await resolveLIDSignalAddress(id);
            const { [wireJid]: existingKey } = await keys.get('identity-key', [wireJid]);
            const keysMatch = existingKey &&
                existingKey.length === identityKey.length &&
                existingKey.every((byte, i) => byte === identityKey[i]);
            if (existingKey && !keysMatch) {
                // Identity changed - clear session and update key
                await keys.set({
                    session: { [wireJid]: null },
                    'identity-key': { [wireJid]: identityKey }
                });
                return true;
            }
            if (!existingKey) {
                // New contact - Trust on First Use (TOFU)
                await keys.set({ 'identity-key': { [wireJid]: identityKey } });
                return true;
            }
            return false;
        },
        loadPreKey: async (id) => {
            const keyId = id.toString();
            const { [keyId]: key } = await keys.get('pre-key', [keyId]);
            if (key) {
                return {
                    privKey: Buffer.from(key.private),
                    pubKey: Buffer.from(key.public)
                };
            }
        },
        removePreKey: (id) => keys.set({ 'pre-key': { [id]: null } }),
        loadSignedPreKey: () => {
            const key = creds.signedPreKey;
            return {
                privKey: Buffer.from(key.keyPair.private),
                pubKey: Buffer.from(key.keyPair.public)
            };
        },
        loadSenderKey: async (senderKeyName) => {
            const keyId = senderKeyName.toString();
            const lidKeyId = await resolveLIDSenderKeyName(keyId);
            const { [lidKeyId]: key } = await keys.get('sender-key', [lidKeyId]);
            if (key) {
                return SenderKeyRecord.deserialize(key);
            }
            // Fallback to original keyId if LID mapping failed or key not found
            if (lidKeyId !== keyId) {
                const { [keyId]: originalKey } = await keys.get('sender-key', [keyId]);
                if (originalKey) {
                    return SenderKeyRecord.deserialize(originalKey);
                }
            }
            return new SenderKeyRecord();
        },
        storeSenderKey: async (senderKeyName, key) => {
            const keyId = senderKeyName.toString();
            const lidKeyId = await resolveLIDSenderKeyName(keyId);
            const serialized = JSON.stringify(key.serialize(), BufferJSON.replacer);
            await keys.set({ 'sender-key': { [lidKeyId]: Buffer.from(serialized, 'utf-8') } });
        },
        getOurRegistrationId: () => creds.registrationId,
        getOurIdentity: () => {
            const { signedIdentityKey } = creds;
            return {
                privKey: Buffer.from(signedIdentityKey.private),
                pubKey: Buffer.from(generateSignalPubKey(signedIdentityKey.public))
            };
        }
    };
    async function resolveLIDSenderKeyName(id) {
        const parts = id.split('::');
        if (parts.length === 3) {
            const [groupId, user, device] = parts;
            if (user && !user.includes('_')) {
                const pnJid = `${user}${device !== '0' ? `:${device}` : ''}@s.whatsapp.net`;
                const lidForPN = await lidMapping.getLIDForPN(pnJid);
                if (lidForPN) {
                    const lidAddr = jidToSignalProtocolAddress(lidForPN);
                    return `${groupId}::${lidAddr.toString().replace('.', '::')}`;
                }
            }
        }
        return id;
    }
}
//# sourceMappingURL=libsignal.js.map