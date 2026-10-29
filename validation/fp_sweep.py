"""False-positive sweep over real code and docs: scan every repo under a root with the directory scanner and
summarise (counts by rule and by file kind; NO previews, NO values). Findings in test fixtures are expected;
anything else should be investigated by hand.

    .venv/bin/python validation/fp_sweep.py /path/to/projects
"""

import asyncio
import collections
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sprawl.llm import NullLLM  # noqa: E402
from sprawl.orchestrator import scan_directory  # noqa: E402


async def main(root: str):
    by_rule: collections.Counter = collections.Counter()
    by_repo: collections.Counter = collections.Counter()
    scanned = 0
    where: dict[str, list[str]] = collections.defaultdict(list)
    for repo in sorted(Path(root).iterdir()):
        if not repo.is_dir() or repo.name.startswith("."):
            continue
        r = await scan_directory(str(repo), NullLLM())
        scanned += r.sources[0].scanned
        for f in r.findings:
            if (
                f.resource.endswith(".env")
                or "/.env" in f.resource
                or f.resource.startswith(".env")
            ):
                continue  # deliberate, gitignored local env files
            by_rule[f.secret_type] += 1
            by_repo[repo.name] += 1
            where[f.secret_type].append(f"{repo.name}/{f.resource}")
    print(f"files scanned: {scanned}")
    print("findings by type:", dict(by_rule))
    for t, locs in where.items():
        print(f"  {t}:")
        for loc in sorted(set(locs))[:12]:
            print("     ", loc)


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1]))
