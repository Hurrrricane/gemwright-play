// 发布版的密码门（publish_web.py 拷进发布目录）。游戏文件用密码加密过：先下载密文，输对密码后在浏览器里解密、解压，
// 再把 blob 地址交给 Unity 的加载器。密码对不对，靠解开 manifest.json 里的 check 判断，不用等游戏文件下完。
(function () {
  var STORE = "gemwright.password";

  function bytes(base64) { return Uint8Array.from(atob(base64), function (c) { return c.charCodeAt(0); }); }

  function remembered() { try { return localStorage.getItem(STORE); } catch (e) { return null; } }
  function remember(password) { try { if (password) localStorage.setItem(STORE, password); else localStorage.removeItem(STORE); } catch (e) {} }

  async function unlock(manifest, password) {
    var base = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
    var key = await crypto.subtle.deriveKey({ name: "PBKDF2", salt: bytes(manifest.salt), iterations: manifest.iterations, hash: "SHA-256" },
      base, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
    try { await crypto.subtle.decrypt({ name: "AES-GCM", iv: bytes(manifest.check.iv) }, key, bytes(manifest.check.data)); return key; }
    catch (e) { return null; }
  }

  // 三个文件一起下，进度条走前一半
  function download(manifest, bar) {
    var total = 0, loaded = {};
    Object.keys(manifest.files).forEach(function (k) { total += manifest.files[k].size; });
    return Promise.all(Object.keys(manifest.files).map(async function (k) {
      var file = manifest.files[k];
      var response = await fetch(file.name);
      if (!response.ok) throw new Error(file.name + " 下载失败（" + response.status + "）");
      var reader = response.body.getReader(), chunks = [], got = 0;
      for (;;) {
        var part = await reader.read();
        if (part.done) break;
        chunks.push(part.value); got += part.value.length; loaded[k] = got;
        var sum = 0; for (var n in loaded) sum += loaded[n];
        bar.style.width = (sum / total * 50) + "%";
      }
      return [k, new Blob(chunks)];
    }));
  }

  async function open(key, file, blob) {
    var plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: bytes(file.iv) }, key, await blob.arrayBuffer());
    var body = new Blob([plain]);
    // 构建是 gzip 压缩的；浏览器能解就自己解，不能解就原样交给 Unity，它的加载器自带解压
    if (file.gzip && window.DecompressionStream) body = await new Response(body.stream().pipeThrough(new DecompressionStream("gzip"))).blob();
    return URL.createObjectURL(new Blob([body], { type: file.type }));
  }

  function ask(manifest) {
    return new Promise(function (resolve) {
      var form = document.querySelector("#gate");
      var input = form.querySelector("input[type=password]");
      var keep = form.querySelector("input[type=checkbox]");
      var hint = form.querySelector(".hint");
      form.style.display = "flex";
      input.focus();
      form.onsubmit = async function (e) {
        e.preventDefault();
        hint.textContent = "";
        var key = await unlock(manifest, input.value);
        if (!key) { hint.textContent = "密码不对"; input.select(); return; }
        remember(keep.checked ? input.value : null);
        form.style.display = "none";
        resolve(key);
      };
    });
  }

  window.gemwrightGate = async function (config, bar) {
    if (!window.crypto || !crypto.subtle) throw new Error("这个页面要用 https 打开");
    var manifest = await (await fetch("manifest.json", { cache: "no-store" })).json();
    var files = download(manifest, bar);
    files.catch(function () {}); // 等输完密码再报错
    // 网址里带 #pw=密码 时直接用，用完从地址栏去掉，免得截图或转发时带出去
    var fromLink = /[#&]pw=([^&]*)/.exec(location.hash);
    if (fromLink) history.replaceState(null, "", location.pathname + location.search);
    var password = fromLink ? decodeURIComponent(fromLink[1]) : remembered();
    var key = password ? await unlock(manifest, password) : null;
    if (key && fromLink) remember(password);
    if (!key) { if (password && !fromLink) remember(null); key = await ask(manifest); }
    var blobs = await files;
    for (var i = 0; i < blobs.length; i++) config[blobs[i][0]] = await open(key, manifest.files[blobs[i][0]], blobs[i][1]);
    // blob 地址每次都不一样，别让 Unity 把它们存进 IndexedDB 缓存
    config.cacheControl = function () { return "no-store"; };
  };
})();
