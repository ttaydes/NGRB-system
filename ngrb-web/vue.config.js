module.exports = {
  transpileDependencies: [], // ✅ 空数组或列出要转译的依赖包名
  chainWebpack: config => {
    config.plugin('html').tap(args => {
      args[0].title = "NGRB-下一代红蓝对抗系统";
      return args;
    });
  }
};
