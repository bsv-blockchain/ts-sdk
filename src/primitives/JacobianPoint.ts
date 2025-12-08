import BasePoint from './BasePoint.js'
import BigNumber from './BigNumber.js'
import Point from './Point.js'

/**
 * The `JacobianPoint` class extends the `BasePoint` class for handling Jacobian coordinates on an Elliptic Curve.
 * This class defines the properties and the methods needed to work with points in Jacobian coordinates.
 *
 * The Jacobian coordinates represent a point (x, y, z) on an Elliptic Curve such that the usual (x, y) coordinates are given by (x/z^2, y/z^3).
 *
 * @property x - The `x` coordinate of the point in the Jacobian form.
 * @property y - The `y` coordinate of the point in the Jacobian form.
 * @property z - The `z` coordinate of the point in the Jacobian form.
 * @property zOne - Flag that indicates if the `z` coordinate is one.
 *
 * @example
 * const pointJ = new JacobianPoint('3', '4', '1');
 */
export default class JacobianPoint extends BasePoint {
  x: BigNumber
  y: BigNumber
  z: BigNumber
  zOne: boolean

  /**
   * Constructs a new `JacobianPoint` instance.
   *
   * @param x - If `null`, the x-coordinate will default to the curve's defined 'one' constant.
   * If `x` is not a BigNumber, `x` will be converted to a `BigNumber` assuming it is a hex string.
   *
   * @param y - If `null`, the y-coordinate will default to the curve's defined 'one' constant.
   * If `y` is not a BigNumber, `y` will be converted to a `BigNumber` assuming it is a hex string.
   *
   * @param z - If `null`, the z-coordinate will default to 0.
   * If `z` is not a BigNumber, `z` will be converted to a `BigNumber` assuming it is a hex string.
   *
   * @example
   * const pointJ1 = new JacobianPoint(null, null, null); // creates point at infinity
   * const pointJ2 = new JacobianPoint('3', '4', '1'); // creates point (3, 4, 1)
   */
  constructor (
    x: string | BigNumber | null,
    y: string | BigNumber | null,
    z: string | BigNumber | null
  ) {
    super('jacobian')
    if (x === null && y === null && z === null) {
      this.x = this.curve.one
      this.y = this.curve.one
      this.z = new BigNumber(0)
    } else {
      if (!BigNumber.isBN(x)) {
        x = new BigNumber(x as string, 16)
      }
      this.x = x as BigNumber
      if (!BigNumber.isBN(y)) {
        y = new BigNumber(y as string, 16)
      }
      this.y = y as BigNumber
      if (!BigNumber.isBN(z)) {
        z = new BigNumber(z as string, 16)
      }
      this.z = z as BigNumber
    }
    if (this.x.red == null) {
      this.x = this.x.toRed(this.curve.red)
    }
    if (this.y.red == null) {
      this.y = this.y.toRed(this.curve.red)
    }
    if (this.z.red == null) {
      this.z = this.z.toRed(this.curve.red)
    }

    this.zOne = this.z === this.curve.one

    // --- Canonicalize point at infinity ---
    if (this.isInfinity()) {
      this.x = this.curve.one
      this.y = this.curve.one
      this.z = new BigNumber(0).toRed(this.curve.red)
      this.zOne = false
    }
  }

  /**
   * Converts the `JacobianPoint` object instance to standard affine `Point` format and returns `Point` type.
   *
   * @returns The `Point`(affine) object representing the same point as the original `JacobianPoint`.
   *
   * If the initial `JacobianPoint` represents point at infinity, an instance of `Point` at infinity is returned.
   *
   * @example
   * const pointJ = new JacobianPoint('3', '4', '1');
   * const pointP = pointJ.toP();  // The point in affine coordinates.
   */
  toP (): Point {
    if (this.isInfinity()) {
      return new Point(null, null)
    }

    const zinv = this.z.redInvm()
    const zinv2 = zinv.redSqr()
    const ax = this.x.redMul(zinv2)
    const ay = this.y.redMul(zinv2).redMul(zinv)

    return new Point(ax, ay)
  }

  /**
   * Negation operation. It returns the additive inverse of the Jacobian point.
   *
   * @method neg
   * @returns Returns a new Jacobian point as the result of the negation.
   *
   * @example
   * const jp = new JacobianPoint(x, y, z)
   * const result = jp.neg()
   */
  neg (): JacobianPoint {
    return new JacobianPoint(this.x, this.y.redNeg(), this.z)
  }

  /**
   * Addition operation in the Jacobian coordinates. It takes a Jacobian point as an argument
   * and returns a new Jacobian point as a result of the addition. In the special cases,
   * when either one of the points is the point at infinity, it will return the other point.
   *
   * @method add
   * @param p - The Jacobian point to be added.
   * @returns Returns a new Jacobian point as the result of the addition.
   *
   * @example
   * const p1 = new JacobianPoint(x1, y1, z1)
   * const p2 = new JacobianPoint(x2, y2, z2)
   * const result = p1.add(p2)
   */
  add (p: JacobianPoint): JacobianPoint {
    // O + P = P
    if (this.isInfinity()) {
      return p
    }

    // P + O = P
    if (p.isInfinity()) {
      return this
    }

    // 12M + 4S + 7A
    const pz2 = p.z.redSqr()
    const z2 = this.z.redSqr()
    const u1 = this.x.redMul(pz2)
    const u2 = p.x.redMul(z2)
    const s1 = this.y.redMul(pz2.redMul(p.z))
    const s2 = p.y.redMul(z2.redMul(this.z))

    const h = u1.redSub(u2)
    const r = s1.redSub(s2)
    if (h.cmpn(0) === 0) {
      if (r.cmpn(0) !== 0) {
        return new JacobianPoint(null, null, null)
      } else {
        return this.dbl()
      }
    }

    const h2 = h.redSqr()
    const h3 = h2.redMul(h)
    const v = u1.redMul(h2)

    const nx = r.redSqr().redIAdd(h3).redISub(v).redISub(v)
    const ny = r.redMul(v.redISub(nx)).redISub(s1.redMul(h3))
    const nz = this.z.redMul(p.z).redMul(h)

    return new JacobianPoint(nx, ny, nz)
  }

  /**
   * Mixed addition operation. This function combines the standard point addition with
   * the transformation from the affine to Jacobian coordinates. It first converts
   * the affine point to Jacobian, and then preforms the addition.
   *
   * @method mixedAdd
   * @param p - The affine point to be added.
   * @returns Returns the result of the mixed addition as a new Jacobian point.
   *
   * @example
   * const jp = new JacobianPoint(x1, y1, z1)
   * const ap = new Point(x2, y2)
   * const result = jp.mixedAdd(ap)
   */
  mixedAdd (p: Point): JacobianPoint {
    // O + P = P
    if (this.isInfinity()) {
      return p.toJ()
    }

    // P + O = P
    if (p.isInfinity()) {
      return this
    }

    // Ensure x and y are not null
    if (p.x === null || p.y === null) {
      throw new Error('Point coordinates cannot be null')
    }

    // 8M + 3S + 7A
    const z2 = this.z.redSqr()
    const u1 = this.x
    const u2 = p.x.redMul(z2)
    const s1 = this.y
    const s2 = p.y.redMul(z2).redMul(this.z)

    const h = u1.redSub(u2)
    const r = s1.redSub(s2)
    if (h.cmpn(0) === 0) {
      if (r.cmpn(0) !== 0) {
        return new JacobianPoint(null, null, null)
      } else {
        return this.dbl()
      }
    }

    const h2 = h.redSqr()
    const h3 = h2.redMul(h)
    const v = u1.redMul(h2)

    const nx = r.redSqr().redIAdd(h3).redISub(v).redISub(v)
    const ny = r.redMul(v.redISub(nx)).redISub(s1.redMul(h3))
    const nz = this.z.redMul(h)

    return new JacobianPoint(nx, ny, nz)
  }

  /**
   * Multiple doubling operation. It doubles the Jacobian point as many times as the pow parameter specifies. If pow is 0 or the point is the point at infinity, it will return the point itself.
   *
   * @method dblp
   * @param pow - The number of times the point should be doubled.
   * @returns Returns a new Jacobian point as the result of multiple doublings.
   *
   * @example
   * const jp = new JacobianPoint(x, y, z)
   * const result = jp.dblp(3)
   */
  dblp (pow: number): JacobianPoint {
    if (pow === 0) {
      return this
    }
    if (this.isInfinity()) {
      return this
    }
    if (typeof pow === 'undefined') {
      return this.dbl()
    }

    /* eslint-disable @typescript-eslint/no-this-alias */
    let r = this as JacobianPoint
    for (let i = 0; i < pow; i++) {
      r = r.dbl()
    }
    return r
  }

  /**
   * Point doubling operation in the Jacobian coordinates. A special case is when the point is the point at infinity, in this case, this function will return the point itself.
   *
   * @method dbl
   * @returns Returns a new Jacobian point as the result of the doubling.
   *
   * @example
   * const jp = new JacobianPoint(x, y, z)
   * const result = jp.dbl()
   */
  dbl (): JacobianPoint {
    if (this.isInfinity()) {
      return this
    }

    let nx
    let ny
    let nz
    // Z = 1
    if (this.zOne) {
      // hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html
      //     #doubling-mdbl-2007-bl
      // 1M + 5S + 14A

      // XX = X1^2
      const xx = this.x.redSqr()
      // YY = Y1^2
      const yy = this.y.redSqr()
      // YYYY = YY^2
      const yyyy = yy.redSqr()
      // S = 2 * ((X1 + YY)^2 - XX - YYYY)
      let s = this.x.redAdd(yy).redSqr().redISub(xx).redISub(yyyy)
      s = s.redIAdd(s)
      // M = 3 * XX + a; a = 0
      const m = xx.redAdd(xx).redIAdd(xx)
      // T = M ^ 2 - 2*S
      const t = m.redSqr().redISub(s).redISub(s)

      // 8 * YYYY
      let yyyy8 = yyyy.redIAdd(yyyy)
      yyyy8 = yyyy8.redIAdd(yyyy8)
      yyyy8 = yyyy8.redIAdd(yyyy8)

      // X3 = T
      nx = t
      // Y3 = M * (S - T) - 8 * YYYY
      ny = m.redMul(s.redISub(t)).redISub(yyyy8)
      // Z3 = 2*Y1
      nz = this.y.redAdd(this.y)
    } else {
      // hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html
      //     #doubling-dbl-2009-l
      // 2M + 5S + 13A

      // A = X1^2
      const a = this.x.redSqr()
      // B = Y1^2
      const b = this.y.redSqr()
      // C = B^2
      const c = b.redSqr()
      // D = 2 * ((X1 + B)^2 - A - C)
      let d = this.x.redAdd(b).redSqr().redISub(a).redISub(c)
      d = d.redIAdd(d)
      // E = 3 * A
      const e = a.redAdd(a).redIAdd(a)
      // F = E^2
      const f = e.redSqr()

      // 8 * C
      let c8 = c.redIAdd(c)
      c8 = c8.redIAdd(c8)
      c8 = c8.redIAdd(c8)

      // X3 = F - 2 * D
      nx = f.redISub(d).redISub(d)
      // Y3 = E * (D - X3) - 8 * C
      ny = e.redMul(d.redISub(nx)).redISub(c8)
      // Z3 = 2 * Y1 * Z1
      nz = this.y.redMul(this.z)
      nz = nz.redIAdd(nz)
    }

    return new JacobianPoint(nx, ny, nz)
  }

  /**
   * Equality check operation. It checks whether the affine or Jacobian point is equal to this Jacobian point.
   *
   * @method eq
   * @param p - The affine or Jacobian point to compare with.
   * @returns Returns true if the points are equal, otherwise returns false.
   *
   * @example
   * const jp1 = new JacobianPoint(x1, y1, z1)
   * const jp2 = new JacobianPoint(x2, y2, z2)
   * const areEqual = jp1.eq(jp2)
   */
  eq (p: Point | JacobianPoint): boolean {
    if (p.type === 'affine') {
      return this.eq((p as Point).toJ())
    }

    if (this === p) {
      return true
    }

    p = p as JacobianPoint

    // --- Infinity handling ---
    if (this.isInfinity() && p.isInfinity()) {
      return true
    }
    if (this.isInfinity() !== p.isInfinity()) {
      return false
    }

    // x1 * z2^2 == x2 * z1^2
    const z2 = this.z.redSqr()
    const pz2 = p.z.redSqr()
    if (this.x.redMul(pz2).redISub(p.x.redMul(z2)).cmpn(0) !== 0) {
      return false
    }

    // y1 * z2^3 == y2 * z1^3
    const z3 = z2.redMul(this.z)
    const pz3 = pz2.redMul(p.z)
    return this.y.redMul(pz3).redISub(p.y.redMul(z3)).cmpn(0) === 0
  }

  /**
   * Equality check operation in relation to an x coordinate of a point in projective coordinates.
   * It checks whether the x coordinate of the Jacobian point is equal to the provided x coordinate
   * of a point in projective coordinates.
   *
   * @method eqXToP
   * @param x - The x coordinate of a point in projective coordinates.
   * @returns Returns true if the x coordinates are equal, otherwise returns false.
   *
   * @example
   * const jp = new JacobianPoint(x1, y1, z1)
   * const isXEqual = jp.eqXToP(x2)
   */
  eqXToP (x: BigNumber): boolean {
    const zs = this.z.redSqr()
    const rx = x.toRed(this.curve?.red).redMul(zs)

    if (this.x.cmp(rx) === 0) {
      return true
    }

    const xc = x.clone()
    if (this.curve === null || (this.curve.redN == null)) {
      throw new Error('Curve or redN is not initialized.')
    }

    const t = this.curve.redN.redMul(zs)

    while (xc.cmp(this.curve.p) < 0) {
      xc.iadd(this.curve.n)
      if (xc.cmp(this.curve.p) >= 0) {
        return false
      }

      rx.redIAdd(t)
      if (this.x.cmp(rx) === 0) {
        return true
      }
    }

    // ✅ Ensure function always returns a boolean
    return false
  }

  /**
   * Returns the string representation of the JacobianPoint instance.
   * @method inspect
   * @returns Returns the string description of the JacobianPoint. If the JacobianPoint represents a point at infinity, the return value of this function is '<EC JPoint Infinity>'. For a normal point, it returns the string description format as '<EC JPoint x: x-coordinate y: y-coordinate z: z-coordinate>'.
   *
   * @example
   * const point = new JacobianPoint('5', '6', '1');
   * console.log(point.inspect()); // Output: '<EC JPoint x: 5 y: 6 z: 1>'
   */
  inspect (): string {
    if (this.isInfinity()) {
      return '<EC JPoint Infinity>'
    }
    return (
      '<EC JPoint x: ' +
      this.x.toString(16, 2) +
      ' y: ' +
      this.y.toString(16, 2) +
      ' z: ' +
      this.z.toString(16, 2) +
      '>'
    )
  }

  /**
   * Checks whether the JacobianPoint instance represents a point at infinity.
   * @method isInfinity
   * @returns Returns true if the JacobianPoint's z-coordinate equals to zero (which represents the point at infinity in Jacobian coordinates). Returns false otherwise.
   *
   * @example
   * const point = new JacobianPoint('5', '6', '0');
   * console.log(point.isInfinity()); // Output: true
   */
  isInfinity (): boolean {
    return this.z.cmpn(0) === 0
  }
}
