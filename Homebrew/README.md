#Anubis

因為本專案太新了，所以目前Homebrew暫時不接收，哭哭。

Anubis is a new project, homebrew is not accept for now.

```
~ % brew audit --strict --online anubis
anubis:
  * GitHub repository not notable enough (<20 forks, <20 watchers and <50 stars)
  * GitHub repository too new (<30 days old)
Error: 2 problems in 1 formula
```

##Manually install

複製```anubis.rb```到``` `brew --prefix`/Library/Taps/homebrew/homebrew-core/Formula/```，然後安裝。

Copy ```anubis.rb``` to ``` `brew --prefix`/Library/Taps/homebrew/homebrew-core/Formula/``` and install it.

```
curl -O https://raw.githubusercontent.com/QbsuranAlang/Anubis/master/Homebrew/anubis.rb
cp anubis.rb `brew --prefix`/Library/Taps/homebrew/homebrew-core/Formula/
brew install anubis
```

##Note

因為目前在Homebrew上沒有```Anubis.rd```，所以每次```brew update```都會刪除```Anubis.rd```。

Because there is no file ```Anubis.rd``` on Homebrew, every ```brew update``` will delete it.

