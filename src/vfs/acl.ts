// Access Control Lists.

import { S_IRWXG } from 'node:constants';
import { assignWithDefaults, deserialize, serialize, sizeof, struct, types as t } from 'utilium';
import { type V_Context } from '../internal/contexts.js';
import { Errno, ErrnoError } from '../internal/error.js';
import { hasAccess, type InodeLike } from '../internal/inode.js';
import { err } from '../internal/log.js';
import { encodeUTF8 } from '../utils.js';
import { S_IRWXO, S_IRWXU } from './constants.js';
import * as xattr from './xattr.js';

const version = 2;

export const enum ACLType {
	Access = 0x8000,
	Default = 0x4000,
}

export const enum ACLTag {
	UserObj = 0x01,
	User = 0x02,
	GroupObj = 0x04,
	Group = 0x08,
	Mask = 0x10,
	Other = 0x20,

	/**
	 * @internal @hidden
	 */
	_None = 0x00,
}

@struct()
export class ACLEntry {
	@t.uint16 public tag: ACLTag = 0;
	@t.uint16 public perm: number = 0;
	@t.uint32 public id: number = 0;

	public constructor(data?: Partial<ACLEntry> | Uint8Array) {
		if (data instanceof Uint8Array) deserialize(this, data);
		else if (typeof data == 'object') assignWithDefaults(this as ACLEntry, data);
	}
}

@struct()
export class ACL {
	@t.uint32 public version: number = version;

	public entries: ACLEntry[] = [];

	public constructor(data?: Uint8Array | ACLEntry[]) {
		if (!data) return;

		if (!(data instanceof Uint8Array)) {
			this.entries.push(...data);
			return;
		}

		deserialize(this, data);

		if (this.version != version) throw err(new ErrnoError(Errno.EINVAL, 'Invalid ACL version'));

		for (let offset = sizeof(ACL); offset < data.length; offset += sizeof(ACLEntry)) {
			if (offset + sizeof(ACLEntry) > data.length) throw err(new ErrnoError(Errno.EIO, 'Invalid ACL data'));

			const slice = data.subarray(offset, offset + sizeof(ACLEntry));

			this.entries.push(new ACLEntry(slice));
		}
	}
}

export function aclFromMode(mode: number): ACL {
	return new ACL([
		new ACLEntry({ tag: ACLTag.UserObj, perm: (mode & S_IRWXU) >> 6 }),
		new ACLEntry({ tag: ACLTag.GroupObj, perm: (mode & S_IRWXG) >> 3 }),
		new ACLEntry({ tag: ACLTag.Other, perm: mode & S_IRWXO }),
	]);
}

export function aclToMode(acl: ACL): number {
	let mode = 0;

	for (const entry of acl.entries) {
		switch (entry.tag) {
			case ACLTag.UserObj:
				mode |= entry.perm << 6;
				break;
			case ACLTag.GroupObj:
				mode |= entry.perm << 3;
				break;
			case ACLTag.Other:
				mode |= entry.perm;
				break;

			case ACLTag.User:
			case ACLTag.Group:
			case ACLTag.Mask:
			case ACLTag._None:
				continue;
		}
	}

	return mode;
}

export async function getACL($: V_Context, path: string): Promise<ACL> {
	return new ACL(await xattr.get.call<V_Context, [string, xattr.Name], Promise<Uint8Array>>($, path, 'system.posix_acl_access'));
}

export function getACLSync($: V_Context, path: string): ACL {
	return new ACL(xattr.getSync.call<V_Context, [string, xattr.Name], Uint8Array>($, path, 'system.posix_acl_access'));
}

export async function setACL($: V_Context, path: string, acl: ACL): Promise<void> {
	await xattr.set.call<V_Context, [string, xattr.Name, Uint8Array], Promise<void>>($, path, 'system.posix_acl_access', serialize(acl));
}

export function setACLSync($: V_Context, path: string, acl: ACL): void {
	xattr.setSync.call<V_Context, [string, xattr.Name, Uint8Array], void>($, path, 'system.posix_acl_access', serialize(acl));
}

export function checkACL($: V_Context, inode: InodeLike, access: number): boolean {
	if (!inode.attributes || !('system.posix_acl_access' in inode.attributes)) return true;

	const mode = aclToMode(new ACL(encodeUTF8(inode.attributes['system.posix_acl_access'])));

	return hasAccess($, { ...inode, mode }, access);
}
