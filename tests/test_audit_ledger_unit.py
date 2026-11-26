        elif sql_upper.startswith("INSERT INTO AUDIT_EVENTS"):
            seq_id = len(self._state["rows"]) + 1
            (
                ts,
                tenant_id,
                endpoint,
                policy_pack,
                policy_version,
                policy_sha256,
                config_fingerprint,
                provenance_hash,
                provenance_json,
                provider,
                action,
                http_status,
                vector,
                redactions_json,
                payload_sha256,
                rounded_latency,
                prev_hash,
                entry_hash,
            ) = params
            self._state["rows"].append(
                {
                    "seq_id": seq_id,
                    "timestamp_utc": ts,
                    "tenant_id": tenant_id,
                    "endpoint": endpoint,
                    "policy_pack": policy_pack,
                    "policy_version": policy_version,
                    "policy_sha256": policy_sha256,
                    "config_fingerprint": config_fingerprint,
                    "provenance_hash": provenance_hash,
                    "provenance_json": provenance_json,
                    "provider": provider,
                    "action": action,
                    "http_status": http_status,
                    "vector": vector,
                    "redactions_json": redactions_json,
                    "payload_sha256": payload_sha256,
                    "latency_ms": rounded_latency,
                    "prev_hash": prev_hash,
                    "entry_hash": entry_hash,
                }
            )
            self._last_result = (seq_id,)