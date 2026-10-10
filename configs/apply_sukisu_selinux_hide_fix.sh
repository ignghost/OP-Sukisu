#!/usr/bin/env bash
set -euo pipefail

: "${KSU_FOLDER:?KSU_FOLDER is required}"
: "${COMMON_KERNEL_FOLDER:?COMMON_KERNEL_FOLDER is required}"
: "${ANDROID_VER_LOCAL:?ANDROID_VER_LOCAL is required}"
: "${KERNEL_VER_LOCAL:?KERNEL_VER_LOCAL is required}"
# SELinux-hide is enabled for supported SukiSU layouts across the workflow. The implementation below validates required files/API before modifying the tree.
ensure_backup_sepolicy_api() {
  local root="$1"
  local header="$root/selinux/sepolicy.h"
  local rules="$root/selinux/rules.c"

  [[ -f "$header" ]] || return 0

  if ! grep -qE '^[[:space:]]*extern[[:space:]]+struct[[:space:]]+selinux_policy[[:space:]]*\*[[:space:]]*backup_sepolicy[[:space:]]*;' "$header"; then
    python3 - "$header" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
s = p.read_text()
line = 'extern struct selinux_policy *backup_sepolicy;'
if line not in s:
    marker = 'struct selinux_policy *ksu_dup_sepolicy(struct selinux_policy *old_pol);'
    if marker in s:
        s = s.replace(marker, line + '\n\n' + marker, 1)
    else:
        s = s.replace('#endif', line + '\n\n#endif', 1)
    p.write_text(s)
PY
  fi

  if [[ -f "$rules" ]] && ! grep -qE '^[[:space:]]*struct[[:space:]]+selinux_policy[[:space:]]*\*[[:space:]]*backup_sepolicy[[:space:]]*;' "$rules"; then
    python3 - "$rules" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
s = p.read_text()
line = 'struct selinux_policy *backup_sepolicy;'
if line not in s:
    marker = '#include "sepolicy.h"'
    if marker in s:
        s = s.replace(marker, marker + '\n\n' + line, 1)
    else:
        s = line + '\n' + s
    p.write_text(s)
PY
  fi

  grep -qE '^[[:space:]]*extern[[:space:]]+struct[[:space:]]+selinux_policy[[:space:]]*\*[[:space:]]*backup_sepolicy[[:space:]]*;' "$header"
  if [[ -f "$rules" ]]; then
    grep -qE '^[[:space:]]*struct[[:space:]]+selinux_policy[[:space:]]*\*[[:space:]]*backup_sepolicy[[:space:]]*;' "$rules"
  fi
}

patch_lsm_hook() {
  local target="$1"
  [[ -f "$target" ]] || return 0

  python3 - "$target" <<'PY'
from pathlib import Path
import re, sys
p = Path(sys.argv[1])
s = p.read_text()

helper = '''static bool ksu_lsm_hook_target_matches(void *current_origin, void *target)
{
    unsigned long start, current_addr;
    unsigned long size = 0, current_size = 0;
    char target_sym[KSYM_SYMBOL_LEN];
    char current_sym[KSYM_SYMBOL_LEN];
    char *p;

    if (!current_origin || !target)
        return false;

    if (current_origin == target)
        return true;

    start = (unsigned long)target;
    current_addr = (unsigned long)current_origin;

    /* First handle normal LTO/ICF aliases which remain inside the symbol. */
    if (kallsyms_lookup_size_offset(start, &size, NULL) && size &&
        current_addr >= start && current_addr < start + size)
        return true;

    /*
     * Some Android 14/6.1 KCFI+LTO builds register a separate local alias
     * (foo.llvm.<hash>) in the LSM hlist.  That alias can sit outside the
     * bare kallsyms symbol range, so compare normalized kallsyms names too.
     */
    if (!kallsyms_lookup(start, &size, NULL, NULL, target_sym))
        return false;
    if (!kallsyms_lookup(current_addr, &current_size, NULL, NULL, current_sym))
        return false;


    p = strstr(target_sym, ".llvm.");
    if (p) *p = '\\0';
    p = strstr(target_sym, ".constprop.");
    if (p) *p = '\\0';
    p = strstr(target_sym, ".isra.");
    if (p) *p = '\\0';
    p = strstr(target_sym, ".part.");
    if (p) *p = '\\0';
    p = strstr(target_sym, ".cfi_jt");
    if (p) *p = '\\0';

    p = strstr(current_sym, ".llvm.");
    if (p) *p = '\\0';
    p = strstr(current_sym, ".constprop.");
    if (p) *p = '\\0';
    p = strstr(current_sym, ".isra.");
    if (p) *p = '\\0';
    p = strstr(current_sym, ".part.");
    if (p) *p = '\\0';
    p = strstr(current_sym, ".cfi_jt");
    if (p) *p = '\\0';

    if (!strcmp(target_sym, current_sym)) {
        pr_info("lsm_hook: alias match %s -> %s\\n", target_sym, current_sym);
        return true;
    }

    return false;
}
'''

if 'ksu_lsm_hook_target_matches' not in s:
    m = re.search(r'\nint\s+ksu_lsm_hook\s*\(\s*struct\s+ksu_lsm_hook\s*\*hook\s*\)\s*\{', s)
    if not m:
        raise SystemExit(f'Cannot locate ksu_lsm_hook() in {p}; refusing unrelated changes')
    s = s[:m.start()] + '\n' + helper + s[m.start():]

pattern = r'if\s*\(\s*current_origin\s*==\s*target\s*\)\s*\{'
s2, n = re.subn(pattern, 'if (ksu_lsm_hook_target_matches(current_origin, target)) {', s)
if n:
    s = s2
elif 'ksu_lsm_hook_target_matches(current_origin, target)' not in s:
    raise SystemExit(f'Cannot locate SukiSU target comparison in {p}; refusing unrelated changes')

p.write_text(s)
PY
}

ensure_backup_sepolicy_api "$KSU_FOLDER/kernel"
ensure_backup_sepolicy_api "$COMMON_KERNEL_FOLDER/drivers/kernelsu"

# The SUSFS enable patch is generated against a newer SukiSU revision than the
# pinned source. On the OP13R Android 14 / 6.1 tree, its SELinux-hide hunks can
# reject while the patch driver removes the .rej files and continues. That leaves
# symbols referenced by SELinux core with file-local (static) definitions. Repair
# only those known cross-translation-unit definitions, then verify each one.
repair_selinux_hide_linkage() {
  local root="$1"
  python3 - "$root" <<'PYLINK'
from pathlib import Path
import re, sys
root = Path(sys.argv[1])
ksu = root / "drivers/kernelsu/feature/selinux_hide.c"
selinuxfs = root / "security/selinux/selinuxfs.c"
for path in (ksu, selinuxfs):
    if not path.is_file():
        raise SystemExit(f"::error::Required SELinux Hide source missing: {path}")

# These symbols are defined by SukiSU's feature/selinux_hide.c. The SUSFS
# compatibility patch may reject the hunk that removes static linkage, so repair
# the definitions in their owning translation unit rather than duplicating them
# in selinuxfs.c.
s = ksu.read_text()
for pat, repl in [
    (r'(?m)^([\t ]*)static[\t ]+bool[\t ]+ksu_selinux_hide_enabled\b', r'\1bool ksu_selinux_hide_enabled'),
    (r'(?m)^([\t ]*)static[\t ]+bool[\t ]+ksu_selinux_hide_running\b', r'\1bool ksu_selinux_hide_running'),
    (r'(?m)^([\t ]*)static[\t ]+struct[\t ]+selinux_state[\t ]+fake_state[\t ]*;', r'\1struct selinux_state fake_state;'),
    (r'(?m)^([\t ]*)static[\t ]+(DEFINE_STATIC_KEY_FALSE[\t ]*\([\t ]*fake_status_initialize_key[\t ]*\)[\t ]*;)', r'\1\2'),
    (r'(?m)^([\t ]*)static[\t ]+(struct[\t ]+page[\t ]*\*[\t ]*fake_status[\t ]*=)', r'\1\2'),
    (r'(?m)^([\t ]*)static[\t ]+void[\t ]+initialize_fake_status[\t ]*\(', r'\1void initialize_fake_status('),
]:
    s = re.sub(pat, repl, s)
ksu.write_text(s)

# Confirm selinuxfs still contains the consumer side; do not add duplicate
# definitions or invent a replacement function body there.
fs = selinuxfs.read_text()
for symbol in ("fake_status_initialize_key", "fake_status", "initialize_fake_status"):
    if symbol not in fs:
        raise SystemExit(f"::error::SELinux Hide consumer symbol {symbol} missing from {selinuxfs}")

print(f"Fixed SELinux Hide cross-file linkage: {ksu.relative_to(root)}")
print(f"Validated SELinux Hide consumers: {selinuxfs.relative_to(root)}")

checks = {
    ksu: [
        r'(?m)^[\t ]*bool[\t ]+ksu_selinux_hide_enabled\b',
        r'(?m)^[\t ]*bool[\t ]+ksu_selinux_hide_running\b',
        r'(?m)^[\t ]*struct[\t ]+selinux_state[\t ]+fake_state[\t ]*;',
        r'(?m)^[\t ]*DEFINE_STATIC_KEY_FALSE[\t ]*\([\t ]*fake_status_initialize_key[\t ]*\)[\t ]*;',
        r'(?m)^[\t ]*struct[\t ]+page[\t ]*\*[\t ]*fake_status[\t ]*=',
        r'(?m)^[\t ]*void[\t ]+initialize_fake_status[\t ]*\(',
    ],
}
for path, patterns in checks.items():
    content = path.read_text()
    for pattern in patterns:
        if not re.search(pattern, content):
            raise SystemExit(f"::error::SELinux Hide global definition missing after repair: {path} / {pattern}")
print("SELinux Hide cross-file symbol definitions validated")
PYLINK
}

patch_lsm_hook "$KSU_FOLDER/kernel/hook/lsm_hook.c"
patch_lsm_hook "$COMMON_KERNEL_FOLDER/drivers/kernelsu/hook/lsm_hook.c"
repair_selinux_hide_linkage "$COMMON_KERNEL_FOLDER"

COMMON_HIDE="$COMMON_KERNEL_FOLDER/drivers/kernelsu/feature/selinux_hide.c"
COMMON_LSM="$COMMON_KERNEL_FOLDER/drivers/kernelsu/hook/lsm_hook.c"
COMMON_SEPOLICY_H="$COMMON_KERNEL_FOLDER/drivers/kernelsu/selinux/sepolicy.h"
COMMON_RULES="$COMMON_KERNEL_FOLDER/drivers/kernelsu/selinux/rules.c"

for f in "$COMMON_HIDE" "$COMMON_LSM" "$COMMON_SEPOLICY_H" "$COMMON_RULES"; do
  [[ -f "$f" ]] || { echo "::error::Missing SukiSU SELinux-hide source: $f"; exit 1; }
done

grep -q 'backup_sepolicy' "$COMMON_HIDE"
grep -qE '^[[:space:]]*extern[[:space:]]+struct[[:space:]]+selinux_policy[[:space:]]*\*[[:space:]]*backup_sepolicy[[:space:]]*;' "$COMMON_SEPOLICY_H"
grep -qE '^[[:space:]]*struct[[:space:]]+selinux_policy[[:space:]]*\*[[:space:]]*backup_sepolicy[[:space:]]*;' "$COMMON_RULES"
grep -q 'ksu_lsm_hook_target_matches(current_origin, target)' "$COMMON_LSM"

echo "SukiSU SELinux-hide API is internally consistent"
echo "  backup_sepolicy: declaration + definition verified"
echo "  common-tree LSM matcher: verified"
echo "  SELinux Hide cross-file linkage: verified"
