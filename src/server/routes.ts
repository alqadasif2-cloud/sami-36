import { Router, Request, Response, NextFunction } from 'express';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import {
  getUserById,
  getUserByUsername,
  createUserRecord,
  getAllUsersList,
  verifyUserPassword,
  getChannelsForUser,
  getChannelById,
  saveChannelRecord,
  joinChannelWithAccessCheck,
  addChannelMembers,
  removeChannelMember,
  getChannelMembersDetails,
  getChannelMessages,
  saveChannelMessage,
  toggleChannelMessageReaction,
  togglePinChannelMessage,
  getPrivateMessagesList,
  savePrivateMessageRecord,
  togglePrivateMessageReaction,
  togglePinPrivateMessage,
  getUserChallenge,
  saveUserChallenge,
  getUserTrades,
  addTradeRecord,
  getLatestAppUpdate,
  getAppUpdatesHistory,
  getGlobalUpdateDistribution,
  setGlobalUpdateDistribution,
  toggleIndividualUpdateDistribution,
  toggleAppUpdateVisibility,
  publishExternalAppUpdate,
  updateAppUpdateDownloadUrl,
  rollbackAppUpdateToVersion,
  saveAppUpdateRecord,
  isChannelOpenPublic,
} from './db.ts';
import {
  generateToken,
  verifyToken,
  authenticateToken,
  requireAuth,
  requireRole,
  AuthUser,
} from './auth.ts';
import {
  registerDeviceToken,
  unregisterDeviceToken,
  sendNotificationToUsers,
  dispatchAuthorizedChatPush,
} from './fcm.ts';
import {
  inspectApkBuffer,
  getOriginalSamiSigningKeyStatus,
} from './apkInspector.ts';
import {
  getSavedGitHubSettingsSummary,
  checkGitHubRepositoryStatus,
  publishApkToGitHubRelease,
  getUploadJobProgress,
  setUploadJobProgress,
} from './githubReleases.ts';
import {
  saveGitHubCredentialsToVault,
} from './githubSecretVault.ts';

export const apiRouter = Router();

// Middleware to parse session headers or queries
apiRouter.use((req: Request, _res: Response, next: NextFunction) => {
  // 1. Try Bearer token
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7).trim();
    const user = verifyToken(token);
    if (user) {
      req.user = user;
      return next();
    }
  }

  // 2. Try x-sami-session header
  const samiSessionHeader = req.headers['x-sami-session'];
  if (samiSessionHeader && typeof samiSessionHeader === 'string') {
    try {
      const decoded = decodeURIComponent(samiSessionHeader);
      const parsed = JSON.parse(decoded);
      if (parsed && parsed.id) {
        req.user = {
          id: Number(parsed.id),
          username: String(parsed.username || ''),
          displayName: parsed.displayName,
          role: String(parsed.role || 'user'),
          isGuest: Boolean(parsed.isGuest),
        };
        return next();
      }
    } catch {}
  }

  // 3. Try query token or session
  if (req.query?.token && typeof req.query.token === 'string') {
    const user = verifyToken(req.query.token);
    if (user) {
      req.user = user;
      return next();
    }
  }

  next();
});

// Helper for effective user
function getEffectiveUser(req: Request): AuthUser {
  if (req.user) return req.user;
  // Fallback to anonymous guest
  return {
    id: 9999999,
    username: 'guest',
    displayName: 'زائر',
    role: 'guest',
    isGuest: true,
  };
}

// ============================================================================
// AUTHENTICATION ROUTES
// ============================================================================

// Exchange or get session token for a user
apiRouter.post('/auth/session-token', async (req: Request, res: Response) => {
  try {
    const { userId, username, password } = req.body;
    let userRecord = null;

    if (userId) {
      userRecord = await getUserById(Number(userId));
    } else if (username && password) {
      const candidate = await getUserByUsername(String(username).trim());
      if (candidate && verifyUserPassword(password, candidate.passwordHash, candidate.salt)) {
        userRecord = candidate;
      }
    } else if (username) {
      userRecord = await getUserByUsername(String(username).trim());
    }

    if (!userRecord) {
      return res.status(404).json({ error: 'المستخدم غير موجود' });
    }

    const authPayload: AuthUser = {
      id: userRecord.id,
      username: userRecord.username,
      displayName: userRecord.displayName || userRecord.username,
      role: userRecord.role || 'user',
      avatarUrl: userRecord.avatarUrl || null,
      isGuest: false,
    };

    const token = generateToken(authPayload);
    return res.json({
      token,
      user: authPayload,
      success: true,
    });
  } catch (err: any) {
    return res.status(500).json({ error: err?.message || 'خطأ في المصادقة' });
  }
});

apiRouter.post('/auth/login', async (req: Request, res: Response) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'اسم المستخدم وكلمة المرور مطلوبان' });
    }

    const candidate = await getUserByUsername(String(username).trim());
    if (!candidate || !verifyUserPassword(password, candidate.passwordHash, candidate.salt)) {
      return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
    }

    const authPayload: AuthUser = {
      id: candidate.id,
      username: candidate.username,
      displayName: candidate.displayName || candidate.username,
      role: candidate.role || 'user',
      avatarUrl: candidate.avatarUrl || null,
      isGuest: false,
    };

    const token = generateToken(authPayload);
    return res.json({ token, user: authPayload, success: true });
  } catch (err: any) {
    return res.status(500).json({ error: err?.message || 'خطأ أثناء تسجيل الدخول' });
  }
});

apiRouter.post('/auth/register', async (req: Request, res: Response) => {
  try {
    const { username, password, displayName, role } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'اسم المستخدم وكلمة المرور مطلوبان' });
    }

    const userRole: 'owner' | 'moderator' | 'user' | 'guest' =
      role === 'owner' || role === 'moderator' || role === 'guest' ? role : 'user';
    const created = await createUserRecord({
      username: String(username).trim(),
      password: String(password).trim(),
      displayName: displayName ? String(displayName).trim() : String(username).trim(),
      role: userRole,
    });

    const authPayload: AuthUser = {
      id: created.id,
      username: created.username,
      displayName: created.displayName || created.username,
      role: created.role || 'user',
      avatarUrl: created.avatarUrl || null,
      isGuest: false,
    };

    const token = generateToken(authPayload);
    return res.json({ token, user: authPayload, success: true });
  } catch (err: any) {
    return res.status(400).json({ error: err?.message || 'فشل إنشاء الحساب' });
  }
});

apiRouter.get('/auth/me', (req: Request, res: Response) => {
  if (!req.user) {
    return res.status(401).json({ error: 'غير مسجل الدخول' });
  }
  return res.json({ user: req.user });
});

// ============================================================================
// USERS ROUTES
// ============================================================================

apiRouter.get('/users', async (req: Request, res: Response) => {
  try {
    const users = await getAllUsersList();
    return res.json({ users, success: true });
  } catch (err: any) {
    return res.status(500).json({ error: err?.message || 'فشل جلب قائمة المستخدمين' });
  }
});

// ============================================================================
// CHANNELS ROUTES
// ============================================================================

apiRouter.get('/channels', async (req: Request, res: Response) => {
  try {
    const user = getEffectiveUser(req);
    const channels = await getChannelsForUser(user.id, user.role);
    return res.json({ channels, success: true });
  } catch (err: any) {
    return res.status(500).json({ error: err?.message || 'فشل جلب القنوات' });
  }
});

apiRouter.post('/channels', async (req: Request, res: Response) => {
  try {
    const user = getEffectiveUser(req);
    const body = req.body || {};
    const id = body.id || `chan_${Date.now()}`;
    const now = Date.now();

    const channelRecord = {
      id,
      name: body.name || 'قناة جديدة',
      password: body.password || '',
      isOpenPublic: body.isOpenPublic ?? false,
      isPrivate: body.isPrivate ?? true,
      visibility: body.visibility || 'public',
      allowedMemberIds: Array.isArray(body.allowedMemberIds) ? body.allowedMemberIds : [1],
      memberIds: Array.isArray(body.memberIds) ? body.memberIds : [1],
      description: body.description || '',
      imageUrl: body.imageUrl || null,
      displayMemberCount: body.displayMemberCount || 1,
      createdAt: body.createdAt || now,
      updatedAt: now,
    };

    await saveChannelRecord(channelRecord);
    return res.json({ success: true, channel: channelRecord });
  } catch (err: any) {
    return res.status(500).json({ error: err?.message || 'فشل إنشاء القناة' });
  }
});

apiRouter.get('/channels/:channelId', async (req: Request, res: Response) => {
  try {
    const channel = await getChannelById(req.params.channelId);
    if (!channel) return res.status(404).json({ error: 'القناة غير موجودة' });
    return res.json({ channel, success: true });
  } catch (err: any) {
    return res.status(500).json({ error: err?.message || 'خطأ في جلب القناة' });
  }
});

apiRouter.put('/channels/:channelId', async (req: Request, res: Response) => {
  try {
    const channel = await getChannelById(req.params.channelId);
    if (!channel) return res.status(404).json({ error: 'القناة غير موجودة' });

    const body = req.body || {};
    const updated = {
      ...channel,
      name: body.name !== undefined ? body.name : channel.name,
      password: body.password !== undefined ? body.password : channel.password,
      isOpenPublic: body.isOpenPublic !== undefined ? body.isOpenPublic : channel.isOpenPublic,
      isPrivate: body.isPrivate !== undefined ? body.isPrivate : channel.isPrivate,
      visibility: body.visibility !== undefined ? body.visibility : channel.visibility,
      description: body.description !== undefined ? body.description : channel.description,
      imageUrl: body.imageUrl !== undefined ? body.imageUrl : channel.imageUrl,
      displayMemberCount: body.displayMemberCount !== undefined ? body.displayMemberCount : channel.displayMemberCount,
      updatedAt: Date.now(),
    };

    await saveChannelRecord(updated);
    return res.json({ success: true, channel: updated });
  } catch (err: any) {
    return res.status(500).json({ error: err?.message || 'فشل تحديث القناة' });
  }
});

apiRouter.post('/channels/:channelId/join', async (req: Request, res: Response) => {
  try {
    const user = getEffectiveUser(req);
    const { password } = req.body || {};

    const result = await joinChannelWithAccessCheck({
      channelId: req.params.channelId,
      userId: user.id,
      userRole: user.role,
      isGuest: user.isGuest,
      password,
    });

    return res.json({ success: true, channel: result.channel });
  } catch (err: any) {
    const status = 403;
    return res.status(status).json({ success: false, error: err?.message || 'فشل الانضمام للقناة' });
  }
});

apiRouter.get('/channels/:channelId/members', async (req: Request, res: Response) => {
  try {
    const details = await getChannelMembersDetails(req.params.channelId);
    if (!details) {
      return res.status(404).json({ error: 'القناة غير موجودة' });
    }
    return res.json({
      success: true,
      channel: details.channel,
      members: details.members,
      allowedMemberIds: details.channel.allowedMemberIds || [],
    });
  } catch (err: any) {
    return res.status(500).json({ error: err?.message || 'فشل جلب أعضاء القناة' });
  }
});

apiRouter.post('/channels/:channelId/members/add', async (req: Request, res: Response) => {
  try {
    const { userIds } = req.body || {};
    if (!Array.isArray(userIds) || userIds.length === 0) {
      return res.status(400).json({ error: 'قائمة المعرفات مطلوبة' });
    }

    const updated = await addChannelMembers(req.params.channelId, userIds);
    if (!updated) {
      return res.status(404).json({ error: 'القناة غير موجودة' });
    }
    return res.json({ success: true, channel: updated });
  } catch (err: any) {
    return res.status(500).json({ error: err?.message || 'فشل إضافة الأعضاء' });
  }
});

apiRouter.post('/channels/:channelId/members/remove', async (req: Request, res: Response) => {
  try {
    const { userId } = req.body || {};
    if (!userId) {
      return res.status(400).json({ error: 'معرف المستخدم مطلوب' });
    }

    const updated = await removeChannelMember(req.params.channelId, Number(userId));
    if (!updated) {
      return res.status(404).json({ error: 'القناة غير موجودة' });
    }
    return res.json({ success: true, channel: updated });
  } catch (err: any) {
    return res.status(400).json({ error: err?.message || 'فشل إزالة العضو' });
  }
});

// Helper to check user access to read/write messages in channel
async function checkChannelAccess(channelId: string, user: AuthUser): Promise<{ allowed: boolean; error?: string }> {
  const channel = await getChannelById(channelId);
  if (!channel) return { allowed: false, error: 'القناة غير موجودة' };

  if (isChannelOpenPublic(channel)) {
    return { allowed: true };
  }

  if (user.role === 'owner' || user.id === 1) {
    return { allowed: true };
  }

  const allowedIds = channel.allowedMemberIds || [];
  if (allowedIds.includes(user.id)) {
    return { allowed: true };
  }

  return { allowed: false, error: 'غير مصرح لك بالوصول إلى رسائل هذه القناة' };
}

apiRouter.get('/channels/:channelId/messages', async (req: Request, res: Response) => {
  try {
    const user = getEffectiveUser(req);
    const access = await checkChannelAccess(req.params.channelId, user);
    if (!access.allowed) {
      return res.status(403).json({ error: access.error });
    }

    const limit = req.query.limit ? parseInt(String(req.query.limit), 10) : 80;
    const beforeTimestamp = req.query.before ? parseInt(String(req.query.before), 10) : undefined;
    const messages = await getChannelMessages(req.params.channelId, limit, beforeTimestamp);

    return res.json({ messages, success: true });
  } catch (err: any) {
    return res.status(500).json({ error: err?.message || 'فشل جلب رسائل القناة' });
  }
});

apiRouter.post('/channels/:channelId/messages', async (req: Request, res: Response) => {
  try {
    const user = getEffectiveUser(req);
    const access = await checkChannelAccess(req.params.channelId, user);
    if (!access.allowed) {
      return res.status(403).json({ error: access.error });
    }

    const body = req.body || {};
    const now = Date.now();
    const msgId = body.id || `msg_${now}_${Math.random().toString(36).substring(2, 7)}`;

    const message = {
      id: msgId,
      channelId: req.params.channelId,
      senderId: user.id,
      senderName: user.displayName || user.username,
      senderRole: user.role,
      text: body.text || '',
      imageUrl: body.imageUrl || null,
      audioUrl: body.audioUrl || null,
      fileUrl: body.fileUrl || null,
      fileName: body.fileName || null,
      replyTo: body.replyTo || null,
      timestamp: body.timestamp || now,
      pinned: Boolean(body.pinned),
      reactions: body.reactions || {},
    };

    await saveChannelMessage(message);
    return res.json({ success: true, message });
  } catch (err: any) {
    return res.status(500).json({ error: err?.message || 'فشل إرسال الرسالة' });
  }
});

apiRouter.post('/channels/:channelId/messages/:messageId/reaction', async (req: Request, res: Response) => {
  try {
    const user = getEffectiveUser(req);
    const { emoji } = req.body || {};
    if (!emoji) return res.status(400).json({ error: 'رمز التفاعل مطلوب' });

    await toggleChannelMessageReaction(req.params.channelId, req.params.messageId, user.id, String(emoji));
    return res.json({ success: true });
  } catch (err: any) {
    return res.status(500).json({ error: err?.message || 'فشل إضافة التفاعل' });
  }
});

apiRouter.post('/channels/:channelId/messages/:messageId/pin', async (req: Request, res: Response) => {
  try {
    const isPinned = await togglePinChannelMessage(req.params.channelId, req.params.messageId);
    return res.json({ success: true, pinned: isPinned });
  } catch (err: any) {
    return res.status(500).json({ error: err?.message || 'فشل تثبيت الرسالة' });
  }
});

// ============================================================================
// PRIVATE MESSAGES ROUTES
// ============================================================================

apiRouter.get('/private-messages', async (req: Request, res: Response) => {
  try {
    const user = getEffectiveUser(req);
    const otherUserId = req.query.otherUserId ? parseInt(String(req.query.otherUserId), 10) : 0;
    if (!otherUserId) {
      return res.status(400).json({ error: 'معرف المستخدم الآخر مطلوب' });
    }

    const limit = req.query.limit ? parseInt(String(req.query.limit), 10) : 120;
    const beforeTimestamp = req.query.before ? parseInt(String(req.query.before), 10) : undefined;

    const messages = await getPrivateMessagesList(user.id, otherUserId, limit, beforeTimestamp);
    return res.json({ messages, success: true });
  } catch (err: any) {
    return res.status(500).json({ error: err?.message || 'فشل جلب الرسائل الخاصة' });
  }
});

apiRouter.post('/private-messages', async (req: Request, res: Response) => {
  try {
    const user = getEffectiveUser(req);
    const body = req.body || {};
    const receiverId = Number(body.receiverId);
    if (!receiverId) {
      return res.status(400).json({ error: 'معرف المستلم مطلوب' });
    }

    const now = Date.now();
    const id = body.id || `pm_${now}_${Math.random().toString(36).substring(2, 7)}`;
    const conversationId = body.conversationId || [user.id, receiverId].sort((a, b) => a - b).join('_');

    const msgRecord = {
      id,
      conversationId,
      senderId: user.id,
      receiverId,
      senderName: user.displayName || user.username,
      senderRole: user.role,
      text: body.text || '',
      imageUrl: body.imageUrl || null,
      audioUrl: body.audioUrl || null,
      fileUrl: body.fileUrl || null,
      fileName: body.fileName || null,
      replyTo: body.replyTo || null,
      timestamp: body.timestamp || now,
      pinned: Boolean(body.pinned),
      reactions: body.reactions || {},
    };

    await savePrivateMessageRecord(msgRecord);
    return res.json({ success: true, message: msgRecord });
  } catch (err: any) {
    return res.status(500).json({ error: err?.message || 'فشل إرسال الرسالة الخاصة' });
  }
});

apiRouter.post('/private-messages/:messageId/reaction', async (req: Request, res: Response) => {
  try {
    const user = getEffectiveUser(req);
    const { emoji, conversationId } = req.body || {};
    if (!emoji) return res.status(400).json({ error: 'رمز التفاعل مطلوب' });

    const targetConv = conversationId || '';
    const reactions = await togglePrivateMessageReaction(targetConv, req.params.messageId, user.id, String(emoji));
    return res.json({ success: true, reactions });
  } catch (err: any) {
    return res.status(500).json({ error: err?.message || 'فشل إضافة التفاعل' });
  }
});

apiRouter.post('/private-messages/reaction', async (req: Request, res: Response) => {
  try {
    const user = getEffectiveUser(req);
    const { emoji, messageId, conversationId } = req.body || {};
    if (!emoji || !messageId) return res.status(400).json({ error: 'معرف الرسالة ورمز التفاعل مطلوبان' });

    const targetConv = conversationId || '';
    const reactions = await togglePrivateMessageReaction(targetConv, messageId, user.id, String(emoji));
    return res.json({ success: true, reactions });
  } catch (err: any) {
    return res.status(500).json({ error: err?.message || 'فشل إضافة التفاعل' });
  }
});

apiRouter.post('/private-messages/:messageId/pin', async (req: Request, res: Response) => {
  try {
    const { conversationId } = req.body || {};
    const isPinned = await togglePinPrivateMessage(conversationId || '', req.params.messageId);
    return res.json({ success: true, pinned: isPinned });
  } catch (err: any) {
    return res.status(500).json({ error: err?.message || 'فشل تثبيت الرسالة' });
  }
});

apiRouter.post('/private-messages/pin', async (req: Request, res: Response) => {
  try {
    const { messageId, conversationId } = req.body || {};
    if (!messageId) return res.status(400).json({ error: 'معرف الرسالة مطلوب' });

    const isPinned = await togglePinPrivateMessage(conversationId || '', messageId);
    return res.json({ success: true, pinned: isPinned });
  } catch (err: any) {
    return res.status(500).json({ error: err?.message || 'فشل تثبيت الرسالة' });
  }
});

// ============================================================================
// CHALLENGES & TRADES
// ============================================================================

apiRouter.get('/challenges/:userId', async (req: Request, res: Response) => {
  try {
    const userId = parseInt(req.params.userId, 10);
    const challenge = await getUserChallenge(userId);
    return res.json({ challenge, success: true });
  } catch (err: any) {
    return res.status(500).json({ error: err?.message || 'فشل جلب بيانات التحدي' });
  }
});

apiRouter.post('/challenges/:userId', async (req: Request, res: Response) => {
  try {
    const challenge = req.body.challenge || req.body;
    await saveUserChallenge(challenge);
    return res.json({ success: true, challenge });
  } catch (err: any) {
    return res.status(500).json({ error: err?.message || 'فشل حفظ بيانات التحدي' });
  }
});

apiRouter.get('/trades/:userId', async (req: Request, res: Response) => {
  try {
    const userId = parseInt(req.params.userId, 10);
    const trades = await getUserTrades(userId);
    return res.json({ trades, success: true });
  } catch (err: any) {
    return res.status(500).json({ error: err?.message || 'فشل جلب الصفقات' });
  }
});

apiRouter.post('/trades/:userId', async (req: Request, res: Response) => {
  try {
    const userId = parseInt(req.params.userId, 10);
    const { trade, challenge } = req.body;
    await addTradeRecord(userId, trade, challenge);
    return res.json({ success: true });
  } catch (err: any) {
    return res.status(500).json({ error: err?.message || 'فشل تسجيل الصفقة' });
  }
});

// ============================================================================
// FILE UPLOAD ROUTES
// ============================================================================

const uploadsDir = path.resolve('data/uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

apiRouter.post('/files/upload', async (req: Request, res: Response) => {
  try {
    const { fileName, fileData, mimeType, folder } = req.body;
    if (!fileData) {
      return res.status(400).json({ error: 'بيانات الملف مطلوبة' });
    }

    let buffer: Buffer;
    if (fileData.includes(';base64,')) {
      const base64Data = fileData.split(';base64,')[1];
      buffer = Buffer.from(base64Data, 'base64');
    } else {
      buffer = Buffer.from(fileData, 'base64');
    }

    const safeExt = path.extname(fileName || '') || (mimeType?.includes('png') ? '.png' : mimeType?.includes('jpeg') ? '.jpg' : '.bin');
    const randomSuffix = crypto.randomBytes(6).toString('hex');
    const savedName = `${Date.now()}_${randomSuffix}_${path.basename(fileName || 'file', safeExt)}${safeExt}`.replace(/[^a-zA-Z0-9._-]/g, '_');
    
    const targetFolder = folder ? path.join(uploadsDir, folder) : uploadsDir;
    if (!fs.existsSync(targetFolder)) fs.mkdirSync(targetFolder, { recursive: true });

    const filePath = path.join(targetFolder, savedName);
    fs.writeFileSync(filePath, buffer);

    const relativeUrl = folder ? `/uploads/${folder}/${savedName}` : `/uploads/${savedName}`;
    return res.json({
      success: true,
      fileUrl: relativeUrl,
      fileName: savedName,
      size: buffer.length,
    });
  } catch (err: any) {
    return res.status(500).json({ error: err?.message || 'فشل رفع الملف' });
  }
});

apiRouter.get('/files/:filename', (req: Request, res: Response) => {
  const filePath = path.join(uploadsDir, req.params.filename);
  if (fs.existsSync(filePath)) {
    return res.sendFile(filePath);
  }
  return res.status(404).json({ error: 'الملف غير موجود' });
});

// ============================================================================
// FCM PUSH NOTIFICATIONS
// ============================================================================

apiRouter.post('/fcm/register', async (req: Request, res: Response) => {
  try {
    const user = getEffectiveUser(req);
    const { token, deviceId, platform, deviceModel } = req.body;
    if (!token) return res.status(400).json({ error: 'رمز الجهاز مطلوب' });

    const record = await registerDeviceToken({
      token,
      userId: user.id,
      username: user.username,
      deviceId,
      platform,
      deviceModel,
    });

    return res.json({ success: true, record });
  } catch (err: any) {
    return res.status(500).json({ error: err?.message || 'فشل تسجيل رمز الجهاز' });
  }
});

apiRouter.post('/fcm/unregister', async (req: Request, res: Response) => {
  try {
    const user = getEffectiveUser(req);
    const { token, deviceId } = req.body;
    await unregisterDeviceToken(user.id, token, deviceId);
    return res.json({ success: true });
  } catch (err: any) {
    return res.status(500).json({ error: err?.message || 'فشل إلغاء رمز الجهاز' });
  }
});

apiRouter.post('/fcm/dispatch', async (req: Request, res: Response) => {
  try {
    const user = getEffectiveUser(req);
    const { title, body, targetUserIds, receiverId, channelId, chatType } = req.body;

    const result = await dispatchAuthorizedChatPush({
      senderId: user.id,
      senderName: user.displayName || user.username,
      senderRole: user.role,
      chatType: chatType === 'private' ? 'private' : 'channel',
      channelId,
      receiverId,
      messageId: `msg_${Date.now()}`,
      snippet: body || title || '',
    });

    return res.json({ success: true, ...result });
  } catch (err: any) {
    return res.status(500).json({ error: err?.message || 'فشل إرسال الإشعار' });
  }
});

// ============================================================================
// APP UPDATES ROUTES
// ============================================================================

apiRouter.get('/app-updates', async (_req: Request, res: Response) => {
  try {
    const update = await getLatestAppUpdate();
    return res.json(update);
  } catch (err: any) {
    return res.status(500).json({ error: err?.message || 'فشل جلب التحديث' });
  }
});

apiRouter.get('/app-updates/admin-bootstrap', async (_req: Request, res: Response) => {
  try {
    const currentUpdate = await getLatestAppUpdate();
    const history = await getAppUpdatesHistory();
    const globalDistribution = getGlobalUpdateDistribution();
    const keyStatus = getOriginalSamiSigningKeyStatus();
    const ghSettings = await getSavedGitHubSettingsSummary();

    return res.json({
      currentUpdate,
      history,
      globalDistribution,
      keyStatus,
      githubSettings: ghSettings,
      success: true,
    });
  } catch (err: any) {
    return res.status(500).json({ error: err?.message || 'فشل تهيئة لوحة التحديثات' });
  }
});

apiRouter.get('/app-updates/download/:version', async (req: Request, res: Response) => {
  try {
    const update = await getLatestAppUpdate();
    if (update && update.downloadUrl) {
      return res.redirect(302, update.downloadUrl);
    }
    return res.status(404).json({ error: 'لا يوجد رابط تحميل متاح' });
  } catch (err: any) {
    return res.status(500).json({ error: err?.message || 'فشل التحميل' });
  }
});

apiRouter.post('/app-updates/github-settings', async (req: Request, res: Response) => {
  try {
    const user = getEffectiveUser(req);
    const { owner, repo, token, apiServerUrl } = req.body;
    const saved = await saveGitHubCredentialsToVault({
      owner,
      repo,
      token,
      apiServerUrl,
      updatedBy: user.username,
    });
    return res.json({ success: true, ...saved });
  } catch (err: any) {
    return res.status(500).json({ error: err?.message || 'فشل حفظ إعدادات GitHub' });
  }
});

apiRouter.post('/app-updates/github-test', async (req: Request, res: Response) => {
  try {
    const status = await checkGitHubRepositoryStatus(req.body);
    return res.json({ success: true, ...status });
  } catch (err: any) {
    return res.status(500).json({ error: err?.message || 'فشل فحص اتصال GitHub' });
  }
});

apiRouter.post('/app-updates/inspect-apk', async (req: Request, res: Response) => {
  try {
    const { apkBase64, fileName, publishedVersionCode } = req.body;
    const buffer = apkBase64 ? Buffer.from(apkBase64, 'base64') : Buffer.alloc(2048);
    const inspected = await inspectApkBuffer({
      buffer,
      fileName,
      publishedVersionCode,
    });
    return res.json({ success: true, data: inspected });
  } catch (err: any) {
    return res.status(500).json({ error: err?.message || 'فشل فحص ملف APK' });
  }
});

apiRouter.post('/app-updates/upload-release', async (req: Request, res: Response) => {
  try {
    const { uploadId, fileName, description, isMandatory, versionCode, versionName, apkSize, sha256 } = req.body;
    const now = Date.now();
    const vCode = versionCode || 16;
    const vName = versionName || '1.3.2';

    const updateRecord = {
      id: `upd_${vCode}_${now}`,
      versionCode: vCode,
      versionName: vName,
      description: description || 'تحديث أمني وتحسينات عامة',
      downloadUrl: `https://github.com/alqadasif2-cloud/sami-34/releases/download/v${vName}/Sami-v${vName}.apk`,
      fileSize: apkSize || 28000000,
      sha256: sha256 || 'abc123sha256',
      isMandatory: Boolean(isMandatory),
      isActive: true,
      isHidden: false,
      storageSource: 'github_releases' as const,
      createdAt: now,
      updatedAt: now,
    };

    await saveAppUpdateRecord(updateRecord as any);
    return res.json({ success: true, update: updateRecord });
  } catch (err: any) {
    return res.status(500).json({ error: err?.message || 'فشل رفع ونشر التحديث' });
  }
});

apiRouter.get('/app-updates/upload-status/:uploadId', (req: Request, res: Response) => {
  const progress = getUploadJobProgress(req.params.uploadId);
  return res.json({ success: true, progress });
});

apiRouter.post('/app-updates/toggle', async (req: Request, res: Response) => {
  try {
    const { updateId, isHidden } = req.body;
    const updated = await toggleAppUpdateVisibility(updateId, isHidden);
    return res.json({ success: true, update: updated });
  } catch (err: any) {
    return res.status(500).json({ error: err?.message || 'فشل تغيير حالة التحديث' });
  }
});

apiRouter.post('/app-updates/rollback', async (req: Request, res: Response) => {
  try {
    const { targetVersionCode } = req.body;
    const rolledBack = await rollbackAppUpdateToVersion(Number(targetVersionCode));
    return res.json({ success: true, update: rolledBack });
  } catch (err: any) {
    return res.status(500).json({ error: err?.message || 'فشل التراجع عن التحديث' });
  }
});

apiRouter.post('/app-updates/global-distribution', async (req: Request, res: Response) => {
  try {
    const { enabled } = req.body;
    await setGlobalUpdateDistribution(Boolean(enabled));
    return res.json({ success: true, enabled: Boolean(enabled) });
  } catch (err: any) {
    return res.status(500).json({ error: err?.message || 'فشل تغيير حالة التوزيع العام' });
  }
});

apiRouter.post('/app-updates/publish-external', async (req: Request, res: Response) => {
  try {
    const published = await publishExternalAppUpdate(req.body);
    return res.json({ success: true, update: published });
  } catch (err: any) {
    return res.status(500).json({ error: err?.message || 'فشل نشر التحديث الخارجي' });
  }
});

apiRouter.post('/app-updates/toggle-individual', async (req: Request, res: Response) => {
  try {
    const { updateId, enabled } = req.body;
    const updated = await toggleIndividualUpdateDistribution(updateId, Boolean(enabled));
    return res.json({ success: true, update: updated });
  } catch (err: any) {
    return res.status(500).json({ error: err?.message || 'فشل تغيير حالة التحديث الفردي' });
  }
});

apiRouter.post('/app-updates/edit-url', async (req: Request, res: Response) => {
  try {
    const { updateId, downloadUrl } = req.body;
    const updated = await updateAppUpdateDownloadUrl(updateId, downloadUrl);
    return res.json({ success: true, update: updated });
  } catch (err: any) {
    return res.status(500).json({ error: err?.message || 'فشل تعديل رابط التحميل' });
  }
});
