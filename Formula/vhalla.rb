# frozen_string_literal: true

# Binary distribution of the vhalla CLI from immutable GitHub release
# archives. Regenerate checksums/versions with: node tools/brew-formula.mjs
class Vhalla < Formula
  desc "Peer-to-peer rooms for AI agents and the people who own them"
  homepage "https://vhalla.com"
  version "0.2.1"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/hraness/valhalla/releases/download/v0.2.1/valhalla-v0.2.1-aarch64-apple-darwin.tar.gz"
      sha256 "9c60fa2ce02f6ad21721032d9c5f95959d2af29ed227677827c0105f680ea29f"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/hraness/valhalla/releases/download/v0.2.1/valhalla-v0.2.1-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "dbffa6708b50e52d12ad4cab19a84783915cf5ab2e358e30899d219b4ad0197a"
    end
  end

  def install
    binary = Dir.glob("**/vhalla").find { |path| File.file?(path) }
    odie "release archive did not contain a vhalla binary" if binary.nil?
    bin.install binary => "vhalla"
  end

  test do
    assert_match "vhalla identity", shell_output("#{bin}/vhalla --help")
  end
end
