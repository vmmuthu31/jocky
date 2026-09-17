# Homebrew formula for JOCKY — Enterprise Digital Forensics Platform
# Install: brew tap vmmuthu31/jocky && brew install jocky
class Jocky < Formula
  desc "Enterprise Digital Forensics Platform — JOCKY DSL compiler & agent"
  homepage "https://github.com/vmmuthu31/jocky"
  version "1.0.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/vmmuthu31/jocky/releases/download/v#{version}/jocky-macos-arm64"
      sha256 :no_check
    else
      url "https://github.com/vmmuthu31/jocky/releases/download/v#{version}/jocky-macos-x86_64"
      sha256 :no_check
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/vmmuthu31/jocky/releases/download/v#{version}/jocky-linux-arm64"
      sha256 :no_check
    else
      url "https://github.com/vmmuthu31/jocky/releases/download/v#{version}/jocky-linux-x86_64"
      sha256 :no_check
    end
  end

  def install
    bin.install Dir["jocky-*"].first => "jocky-compile"
  end

  def post_install
    # Create examples directory
    (share/"jocky/examples").mkpath
  end

  test do
    system "#{bin}/jocky-compile", "--help"
  end
end
