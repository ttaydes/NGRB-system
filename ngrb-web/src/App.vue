<template>
  <div class="app">
    <Header />
    <div class="layout">
      <Sidebar @menu-change="handleMenuChange" />
      <Content :current-menu-index="currentMenuIndex" />
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue';
import Content from "./components/ContentMain.vue";

const currentMenuIndex = ref(0);

const handleMenuChange = (index) => {
  currentMenuIndex.value = index;
};
</script>

<style scoped>
.app {
  display: flex;
  flex-direction: column;
  height: 100vh;
  overflow: hidden;
}

.layout {
  display: flex;
  flex: 1;
  background-color: #f0f2f5;
  overflow: hidden;
}

@media screen and (max-width: 768px) {
  .layout {
    flex-direction: column;
  }
}
</style>