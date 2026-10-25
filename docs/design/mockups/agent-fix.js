// 草图交互：批准框、执行进度和结果。全部是假数据，不发任何请求。
(function () {
  const $ = (id) => document.getElementById(id);
  const mask = $("mask");
  let timers = [];

  function later(ms, fn) {
    timers.push(setTimeout(fn, ms));
  }

  function openFix() {
    $("from").hidden = !$("remote").checked;
    $("who").textContent = $("remote").checked ? "这台电脑的 Agent（问题已交给 Mac mini）" : "这台电脑的 Agent";
    $("ask").hidden = false;
    $("run").hidden = true;
    mask.hidden = false;
    $("later").focus();
  }

  function closeFix() {
    mask.hidden = true;
    $("openFix").focus();
  }

  function mark(id, cls) {
    $(id).className = cls;
  }

  function approve() {
    const fail = $("fail").checked;
    $("ask").hidden = true;
    $("run").hidden = false;
    $("result").hidden = true;
    $("close").hidden = true;
    ["s1", "s2", "s3"].forEach((id) => mark(id, ""));
    $("s3").textContent = "正在确认：打开相册首页";

    mark("s1", "doing");
    later(900, () => { mark("s1", "done"); mark("s2", "doing"); });
    later(2400, () => { mark("s2", "done"); mark("s3", "doing"); });
    later(3900, () => {
      const result = $("result");
      if (fail) {
        mark("s3", "bad");
        $("s3").textContent = "确认失败：容器启动 5 秒后又退出了";
        result.className = "result bad";
        result.textContent = "没修好。容器一启动就退出，日志里写着\"数据库文件被占用\"。我没有再重启。建议先看看是不是另一个程序也在用这个数据目录。";
        $("chat").textContent = "相册没修好：容器一启动就退出（日志：数据库文件被占用）。我停下来了，没有反复重启。";
      } else {
        mark("s3", "done");
        result.className = "result";
        result.textContent = "修好了。两个容器都在运行，相册首页能正常打开（耗时 21 秒）。";
        $("chat").textContent = "相册修好了：我重启了 photos 这一组容器，然后打开相册首页确认能用。记录已保存在 Mac mini 上。";
        $("todo").hidden = true;
        $("bang").style.display = "none";
        $("screen").classList.add("ok");
        $("pcState").textContent = "一切正常";
        $("pcState").classList.add("ok");
        $("photoDot").className = "sq green";
        $("photoState").textContent = "正常";
      }
      result.hidden = false;
      $("close").hidden = false;
      $("close").focus();
    });
  }

  function reset() {
    timers.forEach(clearTimeout);
    timers = [];
    mask.hidden = true;
    $("todo").hidden = false;
    $("bang").style.display = "";
    $("screen").classList.remove("ok");
    $("pcState").textContent = "有 1 件事要处理";
    $("pcState").classList.remove("ok");
    $("photoDot").className = "sq red";
    $("photoState").textContent = "打不开";
    $("chat").textContent = "我查了一下：相册的两个容器 13 分钟前都退出了，日志里最后一行是\"收到停止信号\"，不像程序本身出错。我建议重启这一组容器，请在 Mac mini 头上的感叹号里批准。";
  }

  $("openFix").addEventListener("click", openFix);
  $("bang").addEventListener("click", openFix);
  $("later").addEventListener("click", closeFix);
  $("close").addEventListener("click", closeFix);
  $("approve").addEventListener("click", approve);
  $("reset").addEventListener("click", reset);
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !mask.hidden && !$("ask").hidden) {
      closeFix();
    }
  });
})();
