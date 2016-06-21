class Anubis < Formula
  desc "Powerful packet generator."
  homepage "https://github.com/QbsuranAlang/Anubis"
  url "https://github.com/QbsuranAlang/Anubis/archive/1.1.2-3.tar.gz"
  version "1.1.2-3"
  sha256 "ddd960b95217c7e20c087ce6c3f67f390a9ec126fbbc0be5f6e3b2a426a6842d"

  depends_on "libpcap"
  depends_on "libnet"
  depends_on "libdnet"
  depends_on "openssl"

  def install
    Dir.chdir "Anubis"
    system "./configure", "--disable-dependency-tracking",
                          "--disable-silent-rules",
                          "--prefix=#{prefix}",
                          "--with-libpcap=#{Formula["libpcap"].opt_prefix}",
                          "--with-libnet=#{Formula["libnet"].opt_prefix}",
                          "--with-libdnet=#{Formula["libdnet"].opt_prefix}",
                          "--with-openssl=#{Formula["openssl"].opt_prefix}"
    system "make", "install"
  end

  test do
    system "false"
  end
end
