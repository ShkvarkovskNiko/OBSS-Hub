document.addEventListener('DOMContentLoaded', function() {
    console.log('anima.js загружен');
    const footer = document.getElementById('main-footer');
    
    if (!footer) {
        console.error('Футер с id="main-footer" не найден');
        return;
    }

    // Изначально скрыть футер
    footer.classList.remove('visible');

    function toggleFooter() {
        const isNearBottom = window.innerHeight + window.scrollY >= document.body.offsetHeight - 200;
        if (window.scrollY > 500 || isNearBottom) {
            footer.classList.add('visible');
            console.log('Футер показан');
        } else {
            footer.classList.remove('visible');
            console.log('Футер скрыт');
        }
    }
    
    // Вызов функции сразу после загрузки страницы
    toggleFooter();

    // Добавление слушателя на прокрутку
    window.addEventListener('scroll', toggleFooter);

    // Функция для обновления отступа под футер
    function updateFooterSpace() {
        const footerHeight = footer.offsetHeight;
        const main = document.querySelector('main');
        if (main) {
            main.style.paddingBottom = footerHeight + 40 + 'px';
            console.log('Обновлено пространство под футером:', footerHeight);
        }
    }

    // Вызываем сразу при загрузке страницы
    updateFooterSpace();

    // Добавляем слушатели на изменения размера окна
    window.addEventListener('resize', updateFooterSpace);
});