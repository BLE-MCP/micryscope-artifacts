/**
 * @name MCP crypto misuse (10 rules, path-aware, Python)
 * @description Approximate reimplementation of scan_crypto_misuse_flows_path_aware.py
 *              directly on Python source code, for performance comparison.
 *
 * @kind problem
 * @id mcp/crypto-misuse-path-aware-python
 * @tags security, external/cwe/cwe-327, external/cwe/cwe-759, external/cwe/cwe-760
 */

import python
import semmle.python.dataflow.new.DataFlow

// ===========================================================
// 0. 文件级预过滤：只在“既有 crypto，又有敏感 sink”的文件上跑数据流
// ===========================================================

/** 获取 AST 节点所属文件（用 Location，避免 getFile() 不存在的问题） */
predicate nodeInFile(AstNode n, File f) { f = n.getLocation().getFile() }

/** Logging / print sinks: any argument to print/logging. */
class LoggingSinkExpr extends Expr {
  LoggingSinkExpr() {
    exists(Call c, int i |
      this = c.getArg(i) and
      c.getFunc().toString().regexpMatch("(?i)(^print$|logging\\.|logger\\.|loguru\\.|console\\.log)")
    )
  }
}

/** HTTP request sinks: any argument to requests/httpx/urllib/... */
class HttpSinkExpr extends Expr {
  HttpSinkExpr() {
    exists(Call c, int i |
      this = c.getArg(i) and
      c.getFunc().toString().regexpMatch(
        "(?i)(requests\\.(get|post|put|delete|request)|httpx\\.|urllib\\.|session\\.request|fetch)"
      )
    )
  }
}

/** Return value sink: return expression. */
class ReturnSinkExpr extends Expr {
  ReturnSinkExpr() {
    exists(Return r |
      this = r.getValue()
    )
  }
}

/** Any “sensitive sink” we care about (对应脚本里的 _is_sensitive_sink). */
class SensitiveSinkExpr extends Expr {
  SensitiveSinkExpr() {
    this instanceof LoggingSinkExpr or
    this instanceof HttpSinkExpr or
    this instanceof ReturnSinkExpr
  }
}

// -----------------------------------------------------------
// Helper: crypto-related calls
// -----------------------------------------------------------

/** 统一的“加解密”调用（EncryptCall）。 */
class EncryptCall extends Call {
  EncryptCall() {
    this.getFunc().toString().regexpMatch(
      "(?i)(encrypt|decrypt|cipher|createcipheriv|algorithms\\.aes|aes\\.|rsa\\.|des\\.|openssl_encrypt)"
    )
  }

  /** 可能是 key 的实参（仅使用位置参数，避免 KeywordArg/getAKeywordArgument 不存在）。 */
  Expr getKeyArg() { result = this.getArg(1) }

  /** 可能是 IV 的实参（仅使用位置参数的保守近似：常见为第 3 个参数）。 */
  Expr getIvArg() { result = this.getArg(2) }
}

/** PBKDF2 / KDF 调用。 */
class Pbkdf2Call extends Call {
  Pbkdf2Call() {
    this.getFunc().toString().regexpMatch(
      "(?i)(pbkdf2|pbkdf2_hmac|hashlib\\.pbkdf2_hmac|rfc2898derivebytes)"
    )
  }

  /** 常见 API：pbkdf2*(password, salt, iterations, ...) => salt 取第 2 个参数 */
  Expr getSaltArg() { result = this.getArg(1) }

  /** iterations 常见为第 3 个参数 */
  Expr getIterationsArg() { result = this.getArg(2) }
}

/** MD5 弱哈希。 */
class Md5Call extends Call {
  Md5Call() {
    this.getFunc().toString().regexpMatch("(?i)(hashlib\\.md5|\\bmd5\\b)")
  }
  Expr getDataArg() { result = this.getArg(0) }
}

/** SHA1 弱哈希。 */
class Sha1Call extends Call {
  Sha1Call() {
    this.getFunc().toString().regexpMatch("(?i)(hashlib\\.sha1|\\bsha1\\b)")
  }
  Expr getDataArg() { result = this.getArg(0) }
}

/** DES 使用。 */
class DesCall extends Call {
  DesCall() {
    this.getFunc().toString().regexpMatch("(?i)(des\\.new|des\\.|\\bDES\\b)")
  }
}

/** 固定随机种子（用字符串数字判断，避免 IntLiteral 类型不存在）。 */
class FixedSeedCall extends Call {
  FixedSeedCall() {
    this.getFunc().toString().regexpMatch(
      "(?i)(random\\.seed|np\\.random\\.seed|numpy\\.random\\.seed|torch\\.manual_seed)"
    ) and
    exists(Expr a0 |
      a0 = this.getArg(0) and
      a0.toString().regexpMatch("^[0-9]+$")
    )
  }

  Expr getSeedExpr() { result = this.getArg(0) }
}

/** HMAC / MAC 调用。 */
class MacCall extends Call {
  MacCall() {
    this.getFunc().toString().regexpMatch("(?i)(hmac\\.new|crypto\\.createhmac|hash_hmac|mac\\.getinstance|hmacsha256)")
  }
}

/** 强加密（AES / RSA / DES 等），供 Rule 8 使用。 */
class StrongEncryptionCall extends EncryptCall {
  StrongEncryptionCall() {
    this.getFunc().toString().regexpMatch("(?i)(aes|rsa|des|cipher|encrypt)")
  }
}

// -----------------------------------------------------------
// 文件级过滤：只有“有 crypto 且有敏感 sink”的文件才做 dataflow 判断
// -----------------------------------------------------------

/** 文件是否包含加密调用。 */
predicate fileHasCrypto(File f) {
  exists(EncryptCall c | nodeInFile(c, f)) or
  exists(Md5Call m | nodeInFile(m, f)) or
  exists(Sha1Call s | nodeInFile(s, f))
}

/** 文件是否包含敏感 sink。 */
predicate fileHasSensitiveSink(File f) {
  exists(SensitiveSinkExpr e | nodeInFile(e, f))
}

/** 真正需要做数据流分析的“有意义文件”。 */
predicate interestingFile(File f) {
  fileHasCrypto(f) and fileHasSensitiveSink(f)
}

// -----------------------------------------------------------
// Data-flow: crypto result → Sensitive sink
// -----------------------------------------------------------

/** 是否存在从 e 到任意敏感 sink 的本地数据流。 */
predicate leaksToSensitiveSink(Expr e) {
  exists(DataFlow::Node src, DataFlow::Node sink, File f |
    src.asExpr() = e and
    nodeInFile(e, f) and
    interestingFile(f) and
    sink.asExpr() instanceof SensitiveSinkExpr and
    nodeInFile(sink.asExpr(), f) and
    DataFlow::localFlow(src, sink)
  )
}

// -----------------------------------------------------------
// Rule 实现（10 条规则）
// -----------------------------------------------------------

/** 常量/字面量近似：StringLiteral 或 bytes 风格 b'..' 或纯数字 */
predicate isConstantLike(Expr e) {
  e instanceof StringLiteral or
  e.toString().regexpMatch("(?s)^b['\"].*['\"]$") or
  e.toString().regexpMatch("^[0-9]+$")
}

/** ECB 模式（Rule 1）。 */
predicate rule1_ecb(EncryptCall c, string ruleId, string msg, string evKey, string evMatch) {
  (
    c.getFunc().toString().regexpMatch("(?i)ecb")
    or
    exists(Expr a |
      a = c.getArg(_) and
      a.toString().regexpMatch("(?i)ecb")
    )
  ) and
  ruleId = "Rule 1" and
  evKey  = "ecb_mode" and
  evMatch = "ecb" and
  (
    (leaksToSensitiveSink(c) and msg = "ECB mode detected (result leaked via flow)")
    or
    (not leaksToSensitiveSink(c) and msg = "ECB mode detected")
  )
}

/** CBC + 常量 IV（Rule 9）。 */
predicate rule9_cbc_constant_iv(EncryptCall c, Expr iv, string ruleId, string msg, string evKey, string evMatch) {
  c.getFunc().toString().regexpMatch("(?i)cbc") and
  iv = c.getIvArg() and
  isConstantLike(iv) and
  exists(string ivTxt |
    ivTxt = iv.toString() and
    ruleId = "Rule 9" and
    evKey  = "cbc_constant_iv" and
    evMatch = ivTxt and
    (
      (leaksToSensitiveSink(c) and msg = "CBC with constant IV (result leaked via flow)")
      or
      (not leaksToSensitiveSink(c) and msg = "CBC with constant IV")
    )
  )
}

/** 硬编码加密 key（Rule 2 一部分）。 */
predicate rule2_hardcoded_key(EncryptCall c, Expr key, string ruleId, string msg, string evKey, string evMatch) {
  key = c.getKeyArg() and
  isConstantLike(key) and
  exists(string keyTxt |
    keyTxt = key.toString() and
    ruleId = "Rule 2" and
    evKey  = "hardcoded_key" and
    evMatch = keyTxt and
    (
      (leaksToSensitiveSink(c) and msg = "Hardcoded encryption key detected (ciphertext leaked via flow)")
      or
      (not leaksToSensitiveSink(c) and msg = "Hardcoded encryption key detected")
    )
  )
}

/**
 * 硬编码 LLM API key（Rule 2 另一部分）。
 */
predicate rule2_hardcoded_api_key(Call c, StringLiteral val, string ruleId, string msg, string evKey, string evMatch) {
  exists(StringLiteral k |
    k = c.getArg(_) and
    k.getText().regexpMatch("(?i).*(api[_-]?key|token|access_token|authorization|x-api-key|x-authorization).*")
  ) and
  exists(StringLiteral v |
    v = c.getArg(_) and
    v.getText().regexpMatch(
      "(?i).*(sk-[A-Za-z0-9]{24,}|gsk_[A-Za-z0-9]{24,}|hf_[A-Za-z0-9]{24,}|AIza[0-9A-Za-z_\\-]{24,}).*"
    ) and
    val = v
  ) and
  ruleId = "Rule 2" and
  evKey  = "hardcoded_api_key" and
  evMatch = val.getText() and
  (
    (leaksToSensitiveSink(c) and msg = "Hardcoded API key detected (result leaked via flow)")
    or
    (not leaksToSensitiveSink(c) and msg = "Hardcoded API key detected")
  )
}

/** PBKDF2 常量盐（Rule 10）。 */
predicate rule10_pbkdf2_constant_salt(Pbkdf2Call c, Expr salt, string ruleId, string msg, string evKey, string evMatch) {
  salt = c.getSaltArg() and
  isConstantLike(salt) and
  exists(string saltTxt |
    saltTxt = salt.toString() and
    ruleId = "Rule 10" and
    evKey  = "pbkdf2_constant_salt" and
    evMatch = saltTxt and
    (
      (leaksToSensitiveSink(c) and msg = "Constant salt in PBKDF2 (derived key leaked via flow)")
      or
      (not leaksToSensitiveSink(c) and msg = "Constant salt in PBKDF2")
    )
  )
}

/** PBKDF2 迭代次数过低（Rule 3）：用正则近似 < 1000（1~3 位数字）。 */
predicate rule3_pbkdf2_low_iter(Pbkdf2Call c, Expr itExpr, string ruleId, string msg, string evKey, string evMatch) {
  itExpr = c.getIterationsArg() and
  exists(string itTxt |
    itTxt = itExpr.toString() and
    itTxt.regexpMatch("^[0-9]{1,3}$") and
    ruleId = "Rule 3" and
    evKey  = "pbkdf2_low_iterations" and
    evMatch = itTxt and
    (
      (leaksToSensitiveSink(c) and msg = "Low iteration count in PBKDF2 (derived key leaked via flow)")
      or
      (not leaksToSensitiveSink(c) and msg = "Low iteration count in PBKDF2")
    )
  )
}

/** MD5 在敏感上下文中使用（Rule 4）。 */
predicate rule4_md5_sensitive(Md5Call c, string ruleId, string msg, string evKey, string evMatch) {
  (
    exists(Function f |
      f.getBody().contains(c) and
      f.getName().toLowerCase().regexpMatch("(?i)(token|sign|auth|apikey|login)")
    )
    or
    exists(Expr a |
      a = c.getDataArg() and
      a.toString().regexpMatch("(?i)(token|sign|auth|apikey|secret)")
    )
  ) and
  ruleId = "Rule 4" and
  evKey  = "md5" and
  evMatch = c.getFunc().toString() and
  (
    (leaksToSensitiveSink(c) and msg = "MD5 used in sensitive context (result leaked via flow)")
    or
    (not leaksToSensitiveSink(c) and msg = "MD5 used in sensitive context")
  )
}

/** SHA1 在敏感上下文中使用（Rule 5）。 */
predicate rule5_sha1_sensitive(Sha1Call c, string ruleId, string msg, string evKey, string evMatch) {
  (
    exists(Function f |
      f.getBody().contains(c) and
      f.getName().toLowerCase().regexpMatch("(?i)(token|sign|auth|apikey|login)")
    )
    or
    exists(Expr a |
      a = c.getDataArg() and
      a.toString().regexpMatch("(?i)(token|sign|auth|apikey|secret)")
    )
  ) and
  ruleId = "Rule 5" and
  evKey  = "sha1" and
  evMatch = c.getFunc().toString() and
  (
    (leaksToSensitiveSink(c) and msg = "SHA1 used in sensitive context (result leaked via flow)")
    or
    (not leaksToSensitiveSink(c) and msg = "SHA1 used in sensitive context")
  )
}

/** 固定随机种子（Rule 6）。 */
predicate rule6_fixed_seed(FixedSeedCall c, Expr seedExpr, string ruleId, string msg, string evKey, string evMatch) {
  seedExpr = c.getSeedExpr() and
  exists(string seedTxt |
    seedTxt = seedExpr.toString() and
    seedTxt.regexpMatch("^[0-9]+$") and
    ruleId = "Rule 6" and
    evKey  = "fixed_seed" and
    evMatch = seedTxt and
    (
      (leaksToSensitiveSink(c) and msg = "Fixed RNG seed (result leaked via flow)")
      or
      (not leaksToSensitiveSink(c) and msg = "Fixed RNG seed")
    )
  )
}

/** DES 使用（Rule 7）。 */
predicate rule7_des(DesCall c, string ruleId, string msg, string evKey, string evMatch) {
  ruleId = "Rule 7" and
  evKey  = "des_usage" and
  evMatch = c.getFunc().toString() and
  (
    (leaksToSensitiveSink(c) and msg = "DES usage detected (result leaked via flow)")
    or
    (not leaksToSensitiveSink(c) and msg = "DES usage detected")
  )
}

/** Encryption without MAC（Rule 8，粗略版：同一文件有加密但没有任何 MacCall）。 */
predicate rule8_encryption_no_mac(StrongEncryptionCall c, string ruleId, string msg, string evKey, string evMatch) {
  exists(File f |
    nodeInFile(c, f) and
    not exists(MacCall m | nodeInFile(m, f))
  ) and
  ruleId = "Rule 8" and
  evKey  = "encryption_no_mac" and
  evMatch = c.getFunc().toString() and
  (
    (leaksToSensitiveSink(c) and msg = "Encryption without MAC (ciphertext leaked via flow)")
    or
    (not leaksToSensitiveSink(c) and msg = "Encryption without MAC")
  )
}

// -----------------------------------------------------------
// 汇总所有规则，形成一个统一的 violation 视图
// -----------------------------------------------------------

predicate cryptoViolation(Expr e, string ruleId, string msg, string evKey, string evMatch) {
  exists(EncryptCall c |
    e = c and
    (
      rule1_ecb(c, ruleId, msg, evKey, evMatch) or
      rule9_cbc_constant_iv(c, _, ruleId, msg, evKey, evMatch) or
      rule2_hardcoded_key(c, _, ruleId, msg, evKey, evMatch)
    )
  )
  or
  exists(Call c |
    e = c and
    rule2_hardcoded_api_key(c, _, ruleId, msg, evKey, evMatch)
  )
  or
  exists(Pbkdf2Call p |
    e = p and
    (
      rule10_pbkdf2_constant_salt(p, _, ruleId, msg, evKey, evMatch) or
      rule3_pbkdf2_low_iter(p, _, ruleId, msg, evKey, evMatch)
    )
  )
  or
  exists(Md5Call m |
    e = m and
    rule4_md5_sensitive(m, ruleId, msg, evKey, evMatch)
  )
  or
  exists(Sha1Call s |
    e = s and
    rule5_sha1_sensitive(s, ruleId, msg, evKey, evMatch)
  )
  or
  exists(FixedSeedCall r |
    e = r and
    rule6_fixed_seed(r, _, ruleId, msg, evKey, evMatch)
  )
  or
  exists(DesCall d |
    e = d and
    rule7_des(d, ruleId, msg, evKey, evMatch)
  )
  or
  exists(StrongEncryptionCall se |
    e = se and
    rule8_encryption_no_mac(se, ruleId, msg, evKey, evMatch)
  )
}

// -----------------------------------------------------------
// 最终 select：结果模式必须是 (entity, string)
// -----------------------------------------------------------

from Expr e, string ruleId, string msg, string evKey, string evMatch
where cryptoViolation(e, ruleId, msg, evKey, evMatch)
select e,
  msg + " | Rule: " + ruleId +
  " | EvidenceKey: " + evKey +
  " | EvidenceMatch: " + evMatch
