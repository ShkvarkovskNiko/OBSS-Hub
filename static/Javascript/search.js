document.addEventListener('DOMContentLoaded', function() {
    console.log('search.js загружен');
    const searchForm = document.getElementById('search-form');
    const searchInput = document.getElementById('search-input');
    const searchResults = document.createElement('div');
    searchResults.className = 'search-results';
    
    if (searchForm) {
        searchForm.appendChild(searchResults);
        console.log('Форма поиска найдена');
    } else {
        console.error('Форма поиска с id="search-form" не найдена');
        return;
    }

    async function performSearch(query) {
        console.log('Поиск:', query);
        if (!query.trim()) {
            searchResults.style.display = 'none';
            return;
        }

        try {
            const response = await fetch(`/api/search?query=${encodeURIComponent(query)}`);
            if (!response.ok) {
                throw new Error(`Ошибка HTTP: ${response.status}`);
            }
            const results = await response.json();
            displayResults(results);
        } catch (error) {
            console.error('Ошибка поиска:', error);
            searchResults.innerHTML = '<div class="search-result-item">Ошибка поиска: ' + error.message + '</div>';
            searchResults.style.display = 'block';
        }
    }

    function displayResults(results) {
        searchResults.innerHTML = '';
        console.log('Результаты поиска:', results);
        
        if (results.length === 0) {
            searchResults.innerHTML = '<div class="search-result-item">Ничего не найдено</div>';
            searchResults.style.display = 'block';
            return;
        }

        results.forEach(item => {
            const resultItem = document.createElement('a');
            resultItem.href = `${item.type === 'article' ? 'article.html' : 'events.html'}#${item.id}`;
            resultItem.className = 'search-result-item';
            resultItem.innerHTML = `
                <h4>${item.title}</h4>
                <small>${item.type === 'article' ? 'Статья' : 'Мероприятие'}</small>
            `;
            searchResults.appendChild(resultItem);
        });

        searchResults.style.display = 'block';
    }

    if (searchInput) {
        searchInput.addEventListener('input', function() {
            performSearch(this.value);
        });
    } else {
        console.error('Поле ввода с id="search-input" не найдено');
    }

    searchForm.addEventListener('submit', function(e) {
        e.preventDefault();
        performSearch(searchInput.value);
    });

    document.addEventListener('click', function(e) {
        if (!searchForm.contains(e.target)) {
            searchResults.style.display = 'none';
        }
    });
});