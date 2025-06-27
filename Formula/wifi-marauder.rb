class WifiMarauder < Formula
  desc "WiFi security toolkit"
  homepage "https://github.com/elithaxxor/wifi-maurder-FULL"
  url "https://example.com/wifi-marauder-2.0.0.tar.gz"
  sha256 "deadbeef"
  depends_on "python@3.11"

  def install
    libexec.install Dir["*"]
    bin.install_symlink libexec/"main.py" => "wifi-marauder"
  end
end
