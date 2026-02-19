# Homebrew formula for halt.
#
# To install:
#   brew tap valentinradu/halt https://github.com/valentinradu/Halt
#   brew install halt

class Halt < Formula
  desc "Wrap any process in a filesystem and network sandbox"
  homepage "https://github.com/valentinradu/Halt"
  version "0.0.1"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/valentinradu/Halt/releases/download/v#{version}/halt-aarch64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER_AARCH64_MACOS"
    else
      url "https://github.com/valentinradu/Halt/releases/download/v#{version}/halt-x86_64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER_X86_64_MACOS"
    end
  end

  def install
    bin.install "halt"
  end

  test do
    system bin/"halt", "check"
  end
end
