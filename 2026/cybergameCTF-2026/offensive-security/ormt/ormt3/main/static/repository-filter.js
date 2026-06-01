 (function(){
    const filtersContainer = document.getElementById('filtersContainer');
    const addBtn = document.getElementById('addFilterBtn');
    const filterForm = document.getElementById('filterForm');
    const clearBtn = document.getElementById('filterClear');
    const aggregateSelect = document.getElementById('aggregateSelect');
    const aggregateFieldSelect = document.getElementById('aggregateFieldSelect');

    if(!filtersContainer || !filterForm) return;

    const allowedFields = ['id','title','picture','price','description'];
    const textOps = ['exact','contains'];
    const numericOps = ['exact','gt','lt'];

    function createFieldSelect(selected){
        const sel = document.createElement('select');
        sel.className = 'form-select';
        allowedFields.forEach(f=>{
            const o = document.createElement('option'); o.value = f; o.textContent = f;
            if(f===selected) o.selected = true;
            sel.appendChild(o);
        });
        return sel;
    }

    function makeOpSelectFor(field, selected){
        const sel = document.createElement('select');
        sel.className = 'form-select';
        const ops = (field==='price' || field==='id') ? numericOps : textOps;
        ops.forEach(op=>{
            const o = document.createElement('option'); o.value = op;
            o.textContent = (op==='exact')? 'exact' : (op==='contains'?'contains':(op==='gt'?'greater than':'less than'));
            if(op===selected) o.selected = true;
            sel.appendChild(o);
        });
        return sel;
    }

    function createValueInput(val){
        const inp = document.createElement('input');
        inp.type = 'text';
        inp.className = 'form-control';
        inp.placeholder = 'Value';
        if(val) inp.value = val;
        return inp;
    }

    function createRemoveBtn(){
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'btn btn-outline-danger btn-sm ms-2';
        btn.textContent = 'Remove';
        return btn;
    }

    function createFilterRow(field='title', op='contains', value=''){
        const row = document.createElement('div');
        row.className = 'filter-row d-flex flex-row flex-wrap align-items-center gap-2';

        const fieldSel = createFieldSelect(field);
        const opSel = makeOpSelectFor(field, op);
        const valInp = createValueInput(value);
        const removeBtn = createRemoveBtn();

        const a = document.createElement('div'); a.className = 'me-2'; a.appendChild(fieldSel);
        const b = document.createElement('div'); b.className = 'me-2 op-container'; b.appendChild(opSel);
        const c = document.createElement('div'); c.className = 'me-2 flex-fill'; c.style.minWidth = '160px'; c.appendChild(valInp);
        const d = document.createElement('div'); d.appendChild(removeBtn);

        fieldSel.addEventListener('change', (e)=>{
            const newField = e.target.value;
            const newOp = makeOpSelectFor(newField);
            b.replaceChild(newOp, b.querySelector('select'));
        });

        removeBtn.addEventListener('click', ()=>{ row.remove(); });

        row.appendChild(a); row.appendChild(b); row.appendChild(c); row.appendChild(d);
        filtersContainer.appendChild(row);
        return row;
    }

    function readParamsToRows(){
        const params = new URLSearchParams(window.location.search);
        let found = false;
        for(const [key, val] of params.entries()){
            const m = key.match(/^(.+)__(.+)$/);
            if(m){
                const f = m[1]; const op = m[2];
                if(!allowedFields.includes(f)) continue;
                createFilterRow(f, op, val);
                found = true;
            }
        }
        if(!found) createFilterRow();

        const agg = params.get('aggregate');
        const aggField = params.get('field');
        if(agg && aggregateSelect){
            for(const opt of aggregateSelect.options){ if(opt.value.toLowerCase() === agg.toLowerCase() || opt.text.toLowerCase() === agg.toLowerCase()){ opt.selected = true; break; } }
        }
        if(aggField && aggregateFieldSelect){
            for(const opt of aggregateFieldSelect.options){ if(opt.value === aggField){ opt.selected = true; break; } }
        }
    }

    function buildAndSubmit(){
        const params = new URLSearchParams();
        const rows = filtersContainer.querySelectorAll('.filter-row');
        rows.forEach(row=>{
            const selects = row.querySelectorAll('select');
            const field = selects[0].value;
            const op = selects[1].value;
            const value = row.querySelector('input').value.trim();
            if(value) params.append(`${field}__${op}`, value);
        });
        if(aggregateSelect && aggregateSelect.value){
            params.set('aggregate', aggregateSelect.value);
            if(aggregateFieldSelect && aggregateFieldSelect.value){
                params.set('field', aggregateFieldSelect.value);
            }
        }
        const newUrl = window.location.pathname + (params.toString() ? ('?' + params.toString()) : '');
        window.location.href = newUrl;
    }

    addBtn.addEventListener('click', ()=> createFilterRow());
    filterForm.addEventListener('submit', (e)=>{ e.preventDefault(); buildAndSubmit(); });
    clearBtn.addEventListener('click', ()=>{ window.location.href = window.location.pathname; });

    readParamsToRows();

})();
