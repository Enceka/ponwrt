#!/usr/bin/env python3
"""Check that patch stacking preserves exact generated-source provenance."""
import argparse
import difflib
import json
from pathlib import Path
import tempfile

from source_binding import DRIVER, SourceBinding


HEADER = 'binding.h'


def patch(before, after):
    return ''.join(difflib.unified_diff(before.splitlines(True), after.splitlines(True),
                                       fromfile='a/' + str(DRIVER / HEADER) if before else '/dev/null',
                                       tofile='b/' + str(DRIVER / HEADER)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    outcomes = {}
    scenarios = ('stacked', 'wrong_source', 'missing_overlay', 'offset_hunk',
                 'reordered', 'edited_patch', 'new_overlay', 'edited_source')
    for scenario in scenarios:
        with tempfile.TemporaryDirectory(dir=args.output) as temporary:
            root = Path(temporary)
            patches = root / 'patches'
            source = root / 'source'
            patches.mkdir()
            source.mkdir()
            base = 'base\n'
            logged = 'base\ndiag\n'
            fixed = 'masked\ndiag\n'
            (patches / '001-base.patch').write_text(patch('', base))
            (patches / '002-log.patch').write_text(patch(base, logged))
            (patches / '003-fix.patch').write_text(patch(logged, fixed))
            (source / HEADER).write_text(fixed)
            if scenario == 'wrong_source':
                (source / HEADER).write_text(logged)
            elif scenario == 'missing_overlay':
                (patches / '003-fix.patch').unlink()
            elif scenario == 'offset_hunk':
                (patches / '003-fix.patch').write_text(patch(logged, fixed).replace('-1,2 +1,2', '-2,2 +2,2'))
            elif scenario == 'reordered':
                (patches / '003-fix.patch').rename(patches / '000-fix.patch')
            binding = SourceBinding(patches, root / 'result')
            try:
                binding.bind(source, [HEADER])
                if scenario == 'edited_patch':
                    with (patches / '003-fix.patch').open('a') as stream:
                        stream.write('\n')
                elif scenario == 'new_overlay':
                    (patches / '004-more.patch').write_text(patch(fixed, fixed + 'extra\n'))
                elif scenario == 'edited_source':
                    (source / HEADER).write_text(logged)
                binding.verify_unchanged()
            except (ValueError, RuntimeError) as error:
                if scenario == 'stacked':
                    raise
                outcomes[scenario] = str(error).splitlines()[0]
            else:
                if scenario != 'stacked':
                    raise AssertionError('source-binding negative control survived: ' + scenario)
                outcomes[scenario] = 'matched all three patches'
    report = {'passed': True, 'cases': len(outcomes), 'results': outcomes}
    (args.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
