import { createRouter, createWebHashHistory } from "vue-router";
import Home from "./pages/Home.vue";
import Config from "./pages/Config.vue";

export default createRouter({
  history: createWebHashHistory(),
  routes: [
    { path: "/", name: "home", component: Home },
    { path: "/config", name: "config", component: Config },
  ],
});
