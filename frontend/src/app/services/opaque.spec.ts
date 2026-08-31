import { TestBed } from '@angular/core/testing';

import { Opaque } from './opaque';

describe('Opaque', () => {
  let service: Opaque;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(Opaque);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
