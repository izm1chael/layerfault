#!/usr/bin/env python3
import argparse, pathlib
p=argparse.ArgumentParser()
p.add_argument('--version', required=True)
p.add_argument('--arm-url', required=True)
p.add_argument('--arm-sha256', required=True)
p.add_argument('--intel-url', required=True)
p.add_argument('--intel-sha256', required=True)
p.add_argument('--output', required=True)
a=p.parse_args()
text=f'''class Layerfault < Formula\n  desc "Offline-first local AI model admission and security scanner"\n  homepage "https://github.com/izm1chael/layerfault"\n  version "{a.version.lstrip('v')}"\n  license "MIT"\n\n  on_arm do\n    url "{a.arm_url}"\n    sha256 "{a.arm_sha256}"\n  end\n\n  on_intel do\n    url "{a.intel_url}"\n    sha256 "{a.intel_sha256}"\n  end\n\n  def install\n    bin.install "layerfault"\n  end\n\n  test do\n    assert_match "layerfault", shell_output("#{bin}/layerfault --version")\n  end\nend\n'''
pathlib.Path(a.output).write_text(text)
