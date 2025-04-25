// 페이지 로드 시 실행
document.addEventListener('DOMContentLoaded', function() {
    // 토스트 메시지 자동 닫기
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(function(alert) {
        setTimeout(function() {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }, 5000);
    });
    
    // 이미지 미리보기 (상품 등록/수정 시)
    const imageInput = document.getElementById('image');
    if (imageInput) {
        imageInput.addEventListener('change', function() {
            const previewContainer = document.getElementById('imagePreview');
            if (!previewContainer) {
                const newPreview = document.createElement('div');
                newPreview.id = 'imagePreview';
                newPreview.className = 'mt-2';
                imageInput.parentNode.appendChild(newPreview);
                
                if (this.files && this.files[0]) {
                    const reader = new FileReader();
                    reader.onload = function(e) {
                        newPreview.innerHTML = `
                            <p>이미지 미리보기:</p>
                            <img src="${e.target.result}" class="img-thumbnail" style="max-height: 200px;">
                        `;
                    }
                    reader.readAsDataURL(this.files[0]);
                }
            } else {
                if (this.files && this.files[0]) {
                    const reader = new FileReader();
                    reader.onload = function(e) {
                        previewContainer.innerHTML = `
                            <p>이미지 미리보기:</p>
                            <img src="${e.target.result}" class="img-thumbnail" style="max-height: 200px;">
                        `;
                    }
                    reader.readAsDataURL(this.files[0]);
                } else {
                    previewContainer.innerHTML = '';
                }
            }
        });
    }
    
    // 가격 입력 필드에 콤마 표시
    const priceInputs = document.querySelectorAll('input[name="price"]');
    priceInputs.forEach(function(input) {
        input.addEventListener('input', function() {
            let value = this.value.replace(/,/g, '');
            if (value) {
                this.value = Number(value).toLocaleString('ko-KR');
            }
        });
        
        // 폼 제출 시 콤마 제거
        const form = input.closest('form');
        if (form) {
            form.addEventListener('submit', function() {
                input.value = input.value.replace(/,/g, '');
            });
        }
    });
});
