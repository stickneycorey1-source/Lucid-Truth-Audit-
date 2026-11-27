
diff --git a/lta/audit_ledger.py b/lta/audit_ledger.py
--- a/lta/audit_ledger.py
+++ b/lta/audit_ledger.py
@@
 def _compute_entry_hash(
@@
     policy_sha256: str = "",
     config_fingerprint: str = "",
     provenance_hash: str = "",
+    provenance_json_sha256: str = "",
 ) -> str:
     normalized_redactions = _normalize_redactions(redactions_json)
-    canonical = json.dumps(
-        {
+    canonical_payload = {
             "prev_hash": str(prev_hash),
             "timestamp_utc": str(timestamp_utc),
             "tenant_id": str(tenant_id),
@@
             "payload_sha256": str(payload_sha256),
             "latency_ms": round(float(latency_ms), 3),
-        },
+        }
+
+    # Preserve legacy hash calculations when verifying older records.
+    # New records bind the exact serialized provenance JSON bytes.
+    if provenance_json_sha256:
+        canonical_payload["provenance_json_sha256"] = str(
+            provenance_json_sha256
+        )
+
+    canonical = json.dumps(
+        canonical_payload,
         sort_keys=True,
         separators=(",", ":"),
     )
@@
                 provenance_hash TEXT NOT NULL DEFAULT '',
                 provenance_json TEXT NOT NULL DEFAULT '{}',
+                provenance_json_sha256 TEXT NOT NULL DEFAULT '',
                 provider TEXT NOT NULL,
@@
                 provenance_hash TEXT NOT NULL DEFAULT '',
                 provenance_json TEXT NOT NULL DEFAULT '{}',
+                provenance_json_sha256 TEXT NOT NULL DEFAULT '',
                 provider TEXT NOT NULL,
@@
             "ALTER TABLE audit_events ADD COLUMN provenance_hash TEXT NOT NULL DEFAULT ''",
             "ALTER TABLE audit_events ADD COLUMN provenance_json TEXT NOT NULL DEFAULT '{}'",
+            "ALTER TABLE audit_events ADD COLUMN provenance_json_sha256 TEXT NOT NULL DEFAULT ''",
         ]
@@
             if extra_provenance:
                 prov_dict.update(extra_provenance)
             provenance_json = json.dumps(prov_dict, sort_keys=True, separators=(",", ":"))
+            provenance_json_sha256 = hashlib.sha256(
+                provenance_json.encode("utf-8")
+            ).hexdigest()
 
             entry_hash = _compute_entry_hash(
@@
                 policy_sha256=norm_policy_sha,
                 config_fingerprint=norm_cfg_fp,
                 provenance_hash=prov_hash,
+                provenance_json_sha256=provenance_json_sha256,
             )
             placeholder = "%s" if self._is_postgres else "?"
-            placeholders = ", ".join([placeholder] * 18)
+            placeholders = ", ".join([placeholder] * 19)
             sql = (
                 f"INSERT INTO audit_events "
                 f"(timestamp_utc, tenant_id, endpoint, policy_pack, policy_version, "
                 f"policy_sha256, config_fingerprint, provenance_hash, provenance_json, "
-                f"provider, action, http_status, vector, redactions_json, payload_sha256, "
+                f"provenance_json_sha256, provider, action, http_status, vector, redactions_json, payload_sha256, "
                 f"latency_ms, prev_hash, entry_hash) VALUES ({placeholders})"
             )
@@
                 prov_hash,
                 provenance_json,
+                provenance_json_sha256,
                 provider,
@@
                 "policy_version, policy_sha256, config_fingerprint, provenance_hash, "
-                "provenance_json, provider, action, http_status, vector, "
+                "provenance_json, provenance_json_sha256, provider, action, http_status, vector, "
                 "redactions_json, payload_sha256, latency_ms, prev_hash, entry_hash "
@@
                 provenance_hash,
                 provenance_json,
+                provenance_json_sha256,
                 provider,
@@
             ) = row
             if str(prev_hash) != expected_prev:
                 return False, len(rows), int(seq_id)
 
+            # New records must have an intact provenance JSON digest.
+            # Empty digests identify legacy records created before this migration.
+            stored_provenance_digest = str(provenance_json_sha256 or "")
+            if stored_provenance_digest:
+                actual_provenance_digest = hashlib.sha256(
+                    str(provenance_json).encode("utf-8")
+                ).hexdigest()
+                if actual_provenance_digest != stored_provenance_digest:
+                    return False, len(rows), int(seq_id)
+
             prov_dict = _normalize_provenance_dict(provenance_json)
@@
                 policy_sha256=str(policy_sha256 or ""),
                 config_fingerprint=str(config_fingerprint or ""),
                 provenance_hash=str(provenance_hash or ""),
+                provenance_json_sha256=stored_provenance_digest,
             )
