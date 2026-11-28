      - name: Run hardening & full test suite with branch coverage
        env:
          LUCID_AUDIT_API_KEY: "ci-ephemeral-guard-key"
          LTA_TENANT_KEYS: '{"ci_tenant":"ci-ephemeral-shadow-key"}'
          LUCID_LEDGER_DB_PATH: ":memory:"
        run: |
          shopt -s nullglob
          test_files=(
            tests/test_main_hardening.py
            tests/test_normalizer_hardening.py
            tests/test_ledger_hardening.py
            tests/test_evidence_chain_hardening.py
            tests/test_shadow_hardening.py
            tests/test_logistics_guard_hardening.py
          )
          if [ ${#test_files[@]} -eq 0 ]; then
            echo "No hardening test files found yet; running pytest discovery"
            pytest --cov=app --cov-branch --cov-report=term-missing --cov-report=xml:coverage-${{ matrix.python-version }}.xml -vv
          else
            pytest "${test_files[@]}" --cov=app --cov-branch --cov-report=term-missing --cov-report=xml:coverage-${{ matrix.python-version }}.xml -vv
          fi